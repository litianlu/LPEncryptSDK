//
//  LPEncryptTool.m
//  LPEncryptSDK
//
//  Created by 李天露 on 2017/5/12.
//  Copyright © 2017年 LP. All rights reserved.
//

#import "LPEncryptTool.h"

#define SystemConfig @"SystemConfig"
#define SelectedServer @"SelectedServer"
#define SelectedType @"SelectedType"
#define KEY_CHANGESERVER @"ChangedServer"

@implementation LPEncryptTool

+ (BOOL)isServerProduction {
    NSDictionary *dictionary = [[NSDictionary dictionaryWithContentsOfFile:[[NSBundle mainBundle] pathForResource:SystemConfig ofType:@"plist"]] objectForKey:SelectedServer];
    NSString *selectType = [dictionary objectForKey:SelectedType];
#if DEBUG
    NSString *selectTypeNew = [[NSUserDefaults standardUserDefaults] stringForKey:KEY_CHANGESERVER];
    if (selectTypeNew) {
        selectType = selectTypeNew;
    }
#endif
    return [selectType isEqualToString:@"Production"];
}

@end
