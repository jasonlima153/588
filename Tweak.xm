#import <UIKit/UIKit.h>
#import <AVFoundation/AVFoundation.h>
#import <Security/Security.h>

// ============================================================================
// 一、 运行时动态类与关键方法安全声明（严格遵循原厂报告 10.1 节）
// ============================================================================
@interface AppService : NSObject
+ (id)sharedInstance;
- (void)startSocketService;
@end

static UIBackgroundTaskIdentifier liveBgTaskToken = UIBackgroundTaskInvalid;
static AVAudioPlayer *infiniteKeepAlivePlayer = nil;
static NSTimer *permanentGuardTimer = nil;

// 动态沙盒标识，用于绝对物理隔离多开凭证
static NSString* getSafeInstanceIdentifier(void) {
    static NSString *instanceID = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSString *homeDir = NSHomeDirectory();
        if (homeDir.length > 0) {
            instanceID = [homeDir lastPathComponent];
        } else {
            instanceID = @"CloneDefault";
        }
    });
    return instanceID;
}

// 极其低巧的标准无声音频字节，用于欺骗系统内核，防止后台挂起
static const unsigned char pure_silent_mp3_data[] = {
    0xFF, 0xE3, 0x18, 0xC4, 0x00, 0x00, 0x00, 0x03, 0x48, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x41, 0x4D,
    0x45, 0x33, 0x2E, 0x39, 0x38, 0x2E, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xE3, 0x18, 0xC4, 0x03, 0x00, 0x00, 0x03, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// ============================================================================
// 二、 核心流氓保活：强行激活 iOS 底层多实例混音播放，实现全天候常驻
// ============================================================================
void forceAbsoluteAudioKeepAliveEngine(void) {
    if (!infiniteKeepAlivePlayer) {
        NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
        NSString *audioPath = [docs stringByAppendingPathComponent:@"infinite_loop.mp3"];
        
        if (![[NSFileManager defaultManager] fileExistsAtPath:audioPath]) {
            NSData *d = [NSData dataWithBytes:pure_silent_mp3_data length:sizeof(pure_silent_mp3_data)];
            [d writeToFile:audioPath atomically:YES];
        }
        
        infiniteKeepAlivePlayer = [[AVAudioPlayer alloc] initWithContentsOfURL:[NSURL fileURLWithPath:audioPath] error:nil];
        infiniteKeepAlivePlayer.numberOfLoops = -1;
        [infiniteKeepAlivePlayer prepareToPlay];
    }
    
    // 深度改良多开：同时开启 DuckOthers 和 MixWithOthers
    [[AVAudioSession sharedInstance] setCategory:AVAudioSessionCategoryPlayback 
                                     withOptions:AVAudioSessionCategoryOptionMixWithOthers | AVAudioSessionCategoryOptionDuckOthers
                                           error:nil];
    [[AVAudioSession sharedInstance] setActive:YES error:nil];
    [infiniteKeepAlivePlayer play];
}

%hook AppDelegate

- (void)applicationDidEnterBackground:(UIApplication *)application {
    %orig;
    NSLog(@"[MultiPush] 物理级挂后台全天候常驻保活引擎启动...");
    
    // 1. 强行拉起无感混音音频
    forceAbsoluteAudioKeepAliveEngine();
    
    // 2. 注册标准的持久化后台任务代理
    liveBgTaskToken = [application beginBackgroundTaskWithExpirationHandler:^{
        NSLog(@"[MultiPush] 后台临界点断头台到达，暴力重启混音续命...");
        forceAbsoluteAudioKeepAliveEngine();
        [application endBackgroundTask:liveBgTaskToken];
        liveBgTaskToken = UIBackgroundTaskInvalid;
    }];
    
    // 3. 【核心修复】：建立 10 秒高频网络活性状态纠偏定时器
    if (!permanentGuardTimer) {
        permanentGuardTimer = [NSTimer scheduledTimerWithTimeInterval:10.0 repeats:YES block:^(NSTimer *timer) {
            NSLog(@"[MultiPush] 锁屏状态守护：正在强行清洗 Socket 僵尸状态...");
            
            // 确保混音音频存活
            if (infiniteKeepAlivePlayer && !infiniteKeepAlivePlayer.isPlaying) {
                [[AVAudioSession sharedInstance] setActive:YES error:nil];
                [infiniteKeepAlivePlayer play];
            }
            
            // 【硬核漏洞修复 1】：强制把重连重试计数器抹零
            id autoConnect = [NSClassFromString(@"IMAutoConnectSocket") sharedInstance];
            if (autoConnect) {
                @try {
                    [autoConnect setValue:@(0) forKey:@"reconnectAttempts"];
                    NSLog(@"[MultiPush] 成功阻断重连超限死锁，reconnectAttempts 强制清零");
                } @catch (NSException *e) {
                    NSLog(@"[MultiPush] KVC 拦截失败: %@", e.reason);
                }
            }
            
            // 【硬核漏洞修复 2】：强行触发官方协议层的心跳探测包
            id spSocket = [NSClassFromString(@"SPSocket") sharedInstance];
            SEL heartbeatSel = NSSelectorFromString(@"socketHeartheadReq");
            if ([spSocket respondsToSelector:heartbeatSel]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                [spSocket performSelector:heartbeatSel];
#pragma clang diagnostic pop
            }
            
            // 【硬核漏洞修复 3】：直接暴力拉起总管级网络重建
            AppService *appService = [NSClassFromString(@"AppService") sharedInstance];
            if (appService && [appService respondsToSelector:@selector(startSocketService)]) {
                [appService startSocketService];
            }
        }];
        // 强制塞入系统 CommonModes 核心轮询，确保锁屏绝不断流
        [[NSRunLoop currentRunLoop] addTimer:permanentGuardTimer forMode:NSRunLoopCommonModes];
    }
}

- (void)applicationWillEnterForeground:(UIApplication *)application {
    %orig;
    NSLog(@"[MultiPush] 返回前台，继续维持高强度长连接...");
    forceAbsoluteAudioKeepAliveEngine();
}

%end

// ============================================================================
// 三、 安全 Keychain 隔离（保留登录态不混淆的基础）
// ============================================================================
static OSStatus (*orig_SecItemAdd)(CFDictionaryRef attributes, CFTypeRef *result);
static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef query, CFTypeRef *result);

static CFDictionaryRef createIsolatedAttributes(CFDictionaryRef dict) {
    if (!dict) return NULL;
    NSMutableDictionary *newDict = [(__bridge NSDictionary *)dict mutableCopy];
    newDict[(__bridge id)kSecAttrComment] = getSafeInstanceIdentifier();
    return (__bridge_retained CFDictionaryRef)newDict;
}

OSStatus new_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
    CFDictionaryRef isolated = createIsolatedAttributes(attributes);
    OSStatus status = orig_SecItemAdd(isolated ?: attributes, result);
    if (isolated) CFRelease(isolated);
    return status;
}

OSStatus new_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    CFDictionaryRef isolated = createIsolatedAttributes(query);
    OSStatus status = orig_SecItemCopyMatching(isolated ?: query, result);
    if (isolated) CFRelease(isolated);
    return status;
}

%ctor {
    @autoreleasepool {
        MSHookFunction((void *)SecItemAdd, (void *)new_SecItemAdd, (void **)&orig_SecItemAdd);
        MSHookFunction((void *)SecItemCopyMatching, (void *)new_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching);
    }
}
