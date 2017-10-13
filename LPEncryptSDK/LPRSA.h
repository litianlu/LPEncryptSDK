//
//  RSA.h
//  My
//
//  Created by ideawu on 15-2-3.
//  Copyright (c) 2015年 ideawu. All rights reserved.
//

#import <Foundation/Foundation.h>

/**
 接口类型
 
 - LPAPITypeJAVA: JAVA
 - LPAPITypePHP: PHP
 */
typedef NS_ENUM(NSInteger, LPAPIType) {
    LPAPITypeJAVA = 0,
    LPAPITypePHP = 1,
};

@interface LPRSA : NSObject

/**
 RSA加密
 
 @param str 明文Str
 @param pubKey 指定RSA公钥
 @return RSA密文
 */
+ (NSString *)RSAEncryptString:(NSString *)str publicKey:(NSString *)pubKey;

/**
 RSA加密
 
 @param data 明文Data
 @param pubKey 指定RSA公钥
 @return RSA密文
 */
+ (NSString *)RSAEncryptData:(NSData *)data publicKey:(NSString *)pubKey;

/**
 RSA加密
 
 @param data 明文Data
 @return RSA密文
 */
+ (NSString *)RSAEncryptData:(NSData *)data APIType:(LPAPIType)APIType;

/**
 RSA加密
 
 @param str 明文Str
 @return RSA密文
 */
+ (NSString *)RSAEncryptString:(NSString *)str APIType:(LPAPIType)APIType;

/**
 RSA解密
 
 @param data RSA密文data
 @return 明文
 */
+ (NSData *)RSADecryptData:(NSData *)data APIType:(LPAPIType)APIType;

/**
 RSA解密
 
 @param data RSA密文Data
 @param pubKey 指定RSA公钥
 @return 明文
 */
+ (NSData *)RSADecryptData:(NSData *)data publicKey:(NSString *)pubKey;


/**
 RSA解密

 @param str RSA密文Str
 @return 明文
 */
+ (NSString *)RSADecryptString:(NSString *)str APIType:(LPAPIType)APIType;

/**
 RSA解密

 @param str RSA密文Str
 @param pubKey 指定RSA公钥
 @return 明文
 */
+ (NSString *)RSADecryptString:(NSString *)str publicKey:(NSString *)pubKey;




@end
