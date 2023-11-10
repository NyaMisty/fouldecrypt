//
//  MCMContainerManager.h
//  edgbackup
//
//  Created by Mason Rachel on 10/31/19.
//

#ifndef MCMContainerManager_h
#define MCMContainerManager_h

@interface MCMContainerManager : NSObject

+ (id)defaultManager;

- (id)_containersWithClass:(long long)arg1 temporary:(bool)arg2 error:(id*)arg3;
- (id)containerWithContentClass:(long long)arg1 identifier:(id)arg2 createIfNecessary:(bool)arg3 existed:(bool*)arg4 error:(id*)arg5;
- (id)containerWithContentClass:(long long)arg1 identifier:(id)arg2 error:(id*)arg3;
- (id)containersWithClass:(long long)arg1 error:(id*)arg2;
- (id)deleteContainers:(id)arg1 withCompletion:(id /* block */)arg2;
- (id)init;
- (bool)replaceContainer:(id)arg1 withContainer:(id)arg2 error:(id*)arg3;
- (bool)replaceContainer:(id)arg1 withContainer:(id)arg2 error:(id*)arg3 withCompletion:(id /* block */)arg4;
- (id)temporaryContainerWithContentClass:(long long)arg1 identifier:(id)arg2 existed:(bool*)arg3 error:(id*)arg4;
- (id)temporaryContainersWithClass:(long long)arg1 error:(id*)arg2;

@end

#endif /* MCMContainerManager_h */
