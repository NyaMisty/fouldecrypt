#import <stdio.h>
#import <spawn.h>
#import <objc/runtime.h>

#import <Foundation/Foundation.h>

#import <MobileContainerManager/MCMContainer.h>
#import <MobileCoreServices/LSApplicationProxy.h>
#import <MobileCoreServices/LSApplicationWorkspace.h>

static int VERBOSE = 0;

#define MH_MAGIC_64   0xfeedfacf  /* the 64-bit mach magic number */
#define MH_CIGAM_64   0xcffaedfe  /* NXSwapInt(MH_MAGIC_64) */

#define FAT_MAGIC_64  0xcafebabf
#define FAT_CIGAM_64  0xbfbafeca  /* NXSwapLong(FAT_MAGIC_64) */

extern char **environ;

static NSString *shared_shell_path(void)
{
    static NSString *_sharedShellPath = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ @autoreleasepool {
        NSArray <NSString *> *possibleShells = @[
            @"/usr/bin/bash",
            @"/bin/bash",
            @"/usr/bin/sh",
            @"/bin/sh",
            @"/usr/bin/zsh",
            @"/bin/zsh",
            @"/var/jb/usr/bin/bash",
            @"/var/jb/bin/bash",
            @"/var/jb/usr/bin/sh",
            @"/var/jb/bin/sh",
            @"/var/jb/usr/bin/zsh",
            @"/var/jb/bin/zsh",
        ];
        NSFileManager *fileManager = [NSFileManager defaultManager];
        for (NSString *shellPath in possibleShells) {
            // check if the shell exists and is regular file (not symbolic link) and executable
            NSDictionary <NSFileAttributeKey, id> *shellAttrs = [fileManager attributesOfItemAtPath:shellPath error:nil];
            if ([shellAttrs[NSFileType] isEqualToString:NSFileTypeSymbolicLink]) {
                continue;
            }
            if (![fileManager isExecutableFileAtPath:shellPath]) {
                continue;
            }
            _sharedShellPath = shellPath;
            break;
        }
    } });
    return _sharedShellPath;
}

int
my_system(const char *ctx)
{
    const char *shell_path = [shared_shell_path() UTF8String];
    const char *args[] = {
        shell_path,
        "-c",
        ctx,
        NULL
    };
    pid_t pid;
    int posix_status = posix_spawn(&pid, shell_path, NULL, NULL, (char **) args, environ);
    if (posix_status != 0)
    {
        errno = posix_status;
        fprintf(stderr, "posix_spawn, %s (%d)\n", strerror(errno), errno);
        return posix_status;
    }
    pid_t w;
    int status;
    do
    {
        w = waitpid(pid, &status, WUNTRACED | WCONTINUED);
        if (w == -1)
        {
            fprintf(stderr, "waitpid %d, %s (%d)\n", pid, strerror(errno), errno);
            return errno;
        }
        if (WIFEXITED(status))
        {
            fprintf(stderr, "pid %d exited, status=%d\n", pid, WEXITSTATUS(status));
        }
        else if (WIFSIGNALED(status))
        {
            fprintf(stderr, "pid %d killed by signal %d\n", pid, WTERMSIG(status));
        }
        else if (WIFSTOPPED(status))
        {
            fprintf(stderr, "pid %d stopped by signal %d\n", pid, WSTOPSIG(status));
        }
        else if (WIFCONTINUED(status))
        {
            fprintf(stderr, "pid %d continued\n", pid);
        }
    }
    while (!WIFEXITED(status) && !WIFSIGNALED(status));
    if (WIFSIGNALED(status))
    {
        return WTERMSIG(status);
    }
    return WEXITSTATUS(status);
}

NSString *
escape_arg(NSString *arg)
{
    return [arg stringByReplacingOccurrencesOfString:@"\'" withString:@"'\\\''"];
}

@interface LSApplicationProxy ()
- (NSString *)shortVersionString;
@end

int
main(int argc, char *argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "usage: foulwrapper (application name or application bundle identifier)\n");
        return 1;
    }

    /* Use APIs in `LSApplicationWorkspace`. */
    NSMutableDictionary *appMaps = [NSMutableDictionary dictionary];
    LSApplicationWorkspace *workspace = [LSApplicationWorkspace defaultWorkspace];
    for (LSApplicationProxy *appProxy in [workspace allApplications]) {
        NSString *appId = [appProxy applicationIdentifier];
        NSString *appName = [appProxy localizedName];
        if (appId && appName) {
            appMaps[appId] = appName;
        }
    }

    NSString *targetIdOrName = [NSString stringWithUTF8String:argv[1]];
    NSString *targetId = nil;
    for (NSString *appId in appMaps)
    {
        if ([appId isEqualToString:targetIdOrName] || [appMaps[appId] isEqualToString:targetIdOrName])
        {
            targetId = appId;
            break;
        }
    }

    if (!targetId)
    {
        fprintf(stderr, "application \"%s\" not found\n", argv[1]);
        return 1;
    }


    /* MobileContainerManager: locate app bundle container path */
    /* `LSApplicationProxy` cannot provide correct values of container URLs since iOS 12. */
    NSError *error = nil;
    id aClass = objc_getClass("MCMAppContainer");
    assert([aClass respondsToSelector:@selector(containerWithIdentifier:error:)]);

    MCMContainer *container = [aClass containerWithIdentifier:targetId error:&error];
    NSString *targetPath = [[container url] path];
    if (!targetPath)
    {
        fprintf(stderr,
                "application \"%s\" does not have a bundle container: %s\n",
                argv[1],
                [[error localizedDescription] UTF8String]);
        return 1;
    }
    NSLog(@"%@", targetPath);


    /* Make a copy of app bundle. */
    NSURL *tempURL = [[NSFileManager defaultManager] URLForDirectory:NSItemReplacementDirectory
                                                            inDomain:NSUserDomainMask
                                                   appropriateForURL:[NSURL fileURLWithPath:[[NSFileManager defaultManager] currentDirectoryPath]]
                                                              create:YES error:&error];
    if (!tempURL)
    {
        fprintf(stderr,
                "cannot create appropriate item replacement directory: %s\n",
                [[error localizedDescription] UTF8String]);
        return 1;
    }

    NSString *tempPath = [[tempURL path] stringByAppendingPathComponent:@"Payload"];
    BOOL didCopy = [[NSFileManager defaultManager] copyItemAtPath:targetPath toPath:tempPath error:&error];
    if (!didCopy)
    {
        fprintf(stderr, "cannot copy app bundle: %s\n", [[error localizedDescription] UTF8String]);
        return 1;
    }


    /* Enumerate entire app bundle to find all Mach-Os. */
    NSEnumerator *enumerator = [[NSFileManager defaultManager] enumeratorAtPath:tempPath];
    NSString *objectPath = nil;
    while (objectPath = [enumerator nextObject])
    {
        NSString *objectFullPath = [tempPath stringByAppendingPathComponent:objectPath];
        FILE *fp = fopen(objectFullPath.UTF8String, "rb");
        if (!fp)
        {
            perror("fopen");
            continue;
        }

        int num = getw(fp);
        if (num == EOF)
        {
            fclose(fp);
            continue;
        }

        if (num == MH_MAGIC_64 || num == FAT_MAGIC_64)
        {
            NSString *objectRawPath = [targetPath stringByAppendingPathComponent:objectPath];

            int decryptStatus =
                my_system([[NSString stringWithFormat:@"fouldecrypt -v '%@' '%@'", escape_arg(objectRawPath), escape_arg(
                    objectFullPath)] UTF8String]);
            if (decryptStatus != 0) {
                break;
            }
        }

        fclose(fp);
    }


    /* LSApplicationProxy: get app info */
    LSApplicationProxy *appProxy = [LSApplicationProxy applicationProxyForIdentifier:targetId];
    assert(appProxy);


    /* zip: archive */
    NSString *archiveName =
        [NSString stringWithFormat:@"%@_%@_dumped.ipa", [appProxy localizedName], [appProxy shortVersionString]];
    NSString *archivePath =
        [[[NSFileManager defaultManager] currentDirectoryPath] stringByAppendingPathComponent:archiveName];
    BOOL didClean = [[NSFileManager defaultManager] removeItemAtPath:archivePath error:nil];
    // assert(didClean);
    int zipStatus =
        my_system([[NSString stringWithFormat:@"set -e; shopt -s dotglob; cd '%@'; zip -r '%@' .; shopt -u dotglob;", escape_arg([tempURL path]), escape_arg(
            archivePath)] UTF8String]);

    return zipStatus;
}
