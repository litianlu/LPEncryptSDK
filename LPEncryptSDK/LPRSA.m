//
//  RSA.m
//  My
//
//  Created by ideawu on 15-2-3.
//  Copyright (c) 2015年 ideawu. All rights reserved.
//

#import "LPRSA.h"
#import <Security/Security.h>
#import "LPEncryptTool.h"

#define RSA_KEY_PRO_JAVA @"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCdwcBufwHKfelCZhRmi9oixSB/18zy2CHRjC04FP3GUPE+lXQC9mT/Oj1g7M1wcmiID4U/BWUWfk7ywrXrx9mGkbKhfbz5xB4+QcaP38Z8xwrDjJeET0YvoYDQEA8hPGV9aXFggrie1uaWtKJbDchOsC6n27PgibHGJ+xEw1wORwIDAQAB"

#define RSA_KEY_DEV_JAVA @"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+YbOPFAw69Ii7YEcCc3Mr/t/b8yRFp7wSOXIIa5PLLEQ7up6jRqJ0k59wS2r0tWC9hyva8DhTTfkfSRkGPBPT0TPaD6BQw6rhU15GjmGGA77ZWAtSsm+JrETFzgEbVYMXzDVOufk6dvUYrGogd296I6qOxScGMTr2/CDCmltIYQIDAQAB"

#define RSA_KEY_PRO_PHP @"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+czk0r7UyUE7UfsG8JlwhQo555/sqAHX4qpkhClRKhL7BPF/epnOtvRkjxUwTc5hCbVpBq1M12XCOQ5N37kbaP1tu8DZ2naz9nKsSVSHwCFqdOaFrWZkTxrGzMUlRQ4949pV5ALDP3s52kFPYZq5CyPxrxkDKwawTzYAseP7PMwIDAQAB"

#define RSA_KEY_DEV_PHP @"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDhdewNqvFmb33a+V/hdYmeuwPZqI6UhsryNfyw68Ep/NRxlwysl70HQs8EGAmNLLIhd1qW1/LP3r+szUxiJGOQvBhryHjDP6sENoP3KCZ8h2ElRw5+UZG8C2gLD7LBjNAYiCpPF7x73cygpbt3STgxvb3elhp/fHrzXhcR19cbQwIDAQAB"



#define RSA_KEY_BASE64_JAVA ([LPEncryptTool isServerProduction]) ? (RSA_KEY_PRO_JAVA) : (RSA_KEY_DEV_JAVA)

#define RSA_KEY_BASE64_PHP ([LPEncryptTool isServerProduction]) ? (RSA_KEY_PRO_PHP) : (RSA_KEY_DEV_PHP)

@implementation LPRSA

/*
static NSString *base64_encode(NSString *str){
	NSData* data = [str dataUsingEncoding:NSUTF8StringEncoding];
	if(!data){
		return nil;
	}
	return base64_encode_data(data);
}
*/

static NSString *base64_encode_data(NSData *data){
	data = [data base64EncodedDataWithOptions:0];
	NSString *ret = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
	return ret;
}

static NSData *base64_decode(NSString *str){
	NSData *data = [[NSData alloc] initWithBase64EncodedString:str options:NSDataBase64DecodingIgnoreUnknownCharacters];
	return data;
}

+ (NSData *)stripPublicKeyHeader:(NSData *)d_key{
    // Skip ASN.1 public key header
    if (d_key == nil) return(nil);
    
    unsigned long len = [d_key length];
    if (!len) return(nil);
    
    unsigned char *c_key = (unsigned char *)[d_key bytes];
    unsigned int  idx	 = 0;
    
    if (c_key[idx++] != 0x30) return(nil);
    
    if (c_key[idx] > 0x80) idx += c_key[idx] - 0x80 + 1;
    else idx++;
    
    // PKCS #1 GTRSAEncryption szOID_GTRSA_GTRSA
    static unsigned char seqiod[] =
    { 0x30,   0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x01, 0x05, 0x00 };
    if (memcmp(&c_key[idx], seqiod, 15)) return(nil);
    
    idx += 15;
    
    if (c_key[idx++] != 0x03) return(nil);
    
    if (c_key[idx] > 0x80) idx += c_key[idx] - 0x80 + 1;
    else idx++;
    
    if (c_key[idx++] != '\0') return(nil);
    
    // Now make a new NSData from this buffer
    return([NSData dataWithBytes:&c_key[idx] length:len - idx]);
}

+ (SecKeyRef)addPublicKey:(NSString *)key{
    NSRange spos = [key rangeOfString:@"-----BEGIN PUBLIC KEY-----"];
    NSRange epos = [key rangeOfString:@"-----END PUBLIC KEY-----"];
    if(spos.location != NSNotFound && epos.location != NSNotFound){
        NSUInteger s = spos.location + spos.length;
        NSUInteger e = epos.location;
        NSRange range = NSMakeRange(s, e-s);
        key = [key substringWithRange:range];
    }
    key = [key stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\t" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@" "  withString:@""];
    
    // This will be base64 encoded, decode it.
    NSData *data = base64_decode(key);
    data = [LPRSA stripPublicKeyHeader:data];
    if(!data){
        return nil;
    }
    
    //a tag to read/write keychain storage
    NSString *tag = @"what_the_fuck_is_this";
    NSData *d_tag = [NSData dataWithBytes:[tag UTF8String] length:[tag length]];
    
    // Delete any old lingering key with the same tag
    NSMutableDictionary *publicKey = [[NSMutableDictionary alloc] init];
    [publicKey setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
    [publicKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [publicKey setObject:d_tag forKey:(__bridge id)kSecAttrApplicationTag];
    SecItemDelete((__bridge CFDictionaryRef)publicKey);
    
    // Add persistent version of the key to system keychain
    [publicKey setObject:data forKey:(__bridge id)kSecValueData];
    [publicKey setObject:(__bridge id) kSecAttrKeyClassPublic forKey:(__bridge id)
     kSecAttrKeyClass];
    [publicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)
     kSecReturnPersistentRef];
    
    CFTypeRef persistKey = nil;
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)publicKey, &persistKey);
    if (persistKey != nil){
        CFRelease(persistKey);
    }
    if ((status != noErr) && (status != errSecDuplicateItem)) {
        return nil;
    }
    
    [publicKey removeObjectForKey:(__bridge id)kSecValueData];
    [publicKey removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
    [publicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    [publicKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    // Now fetch the SecKeyRef version of the key
    SecKeyRef keyRef = nil;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)publicKey, (CFTypeRef *)&keyRef);
    if(status != noErr){
        return nil;
    }
    return keyRef;
}

+ (NSString *)RSAEncryptString:(NSString *)str APIType:(LPAPIType)APIType
{
    NSString *encryptedString = nil;
    NSData *stringData = [str dataUsingEncoding:NSUTF8StringEncoding];
    if(stringData.length >= 117){
        int midOffset = (int)str.length/2;
        
        NSRange rangeIndex = [str rangeOfComposedCharacterSequenceAtIndex:midOffset];
        NSString *string1 = [str substringToIndex:rangeIndex.location];
        NSString *string2 = [str substringFromIndex:rangeIndex.location];
        NSString *encryptedString1 = [LPRSA RSAEncryptString:string1 APIType:APIType];
        NSString *encryptedString2 = [LPRSA RSAEncryptString:string2 APIType:APIType];
        encryptedString = [NSString stringWithFormat:@"%@,%@",encryptedString1,encryptedString2];
    }else{
        switch (APIType) {
            case LPAPITypeJAVA:
                encryptedString = [LPRSA RSAEncryptString:str publicKey:RSA_KEY_BASE64_JAVA];
                break;
            case LPAPITypePHP:
                encryptedString = [LPRSA RSAEncryptString:str publicKey:RSA_KEY_BASE64_PHP];
                break;
                
            default:
                break;
        }
    }
    return encryptedString;;
}

+ (NSString *)RSAEncryptString:(NSString *)str publicKey:(NSString *)pubKey{
	NSData* data = [str dataUsingEncoding:NSUTF8StringEncoding];
	return [LPRSA RSAEncryptData:data publicKey:pubKey];
}

+ (NSString *)RSAEncryptData:(NSData *)data APIType:(LPAPIType)APIType {
    switch (APIType) {
        case LPAPITypeJAVA:
            return [LPRSA RSAEncryptData:data publicKey:RSA_KEY_BASE64_JAVA];
            break;
        case LPAPITypePHP:
            return [LPRSA RSAEncryptData:data publicKey:RSA_KEY_BASE64_PHP];
            break;
        default:
            return nil;
            break;
    }
}

+ (NSString *)RSAEncryptData:(NSData *)data publicKey:(NSString *)pubKey{
	if(!data || !pubKey){
		return nil;
	}
	SecKeyRef keyRef = [LPRSA addPublicKey:pubKey];
	if(!keyRef){
		return nil;
	}
	
	const uint8_t *srcbuf = (const uint8_t *)[data bytes];
	size_t srclen = (size_t)data.length;
	
	size_t outlen = SecKeyGetBlockSize(keyRef) * sizeof(uint8_t);
	if(srclen > outlen - 11){
		CFRelease(keyRef);
		return nil;
	}
	void *outbuf = malloc(outlen);
	
	OSStatus status = noErr;
	status = SecKeyEncrypt(keyRef,
                           kSecPaddingPKCS1,//4806之后采用补充算法
						   srcbuf,
						   srclen,
						   outbuf,
						   &outlen
						   );
	NSString *ret = nil;
	if (status != 0) {
		//NSLog(@"SecKeyEncrypt fail. Error Code: %ld", status);
	}else{
		NSData *data = [NSData dataWithBytes:outbuf length:outlen];
		ret = base64_encode_data(data);
	}
	free(outbuf);
	CFRelease(keyRef);
	return ret;
}

+ (NSData *)RSADecryptData:(NSData *)data APIType:(LPAPIType)APIType {
    switch (APIType) {
        case LPAPITypeJAVA:
            return [LPRSA RSADecryptData:data publicKey:RSA_KEY_BASE64_JAVA];
            break;
        case LPAPITypePHP:
            return [LPRSA RSADecryptData:data publicKey:RSA_KEY_BASE64_PHP];
            break;
        default:
            return nil;
            break;
    }
}

+ (NSData *)RSADecryptData:(NSData *)data publicKey:(NSString *)pubKey{
    if(!data || !pubKey){
        return nil;
    }
    SecKeyRef keyRef = [LPRSA addPublicKey:pubKey];
    if(!keyRef){
        return nil;
    }
    return [LPRSA decryptData:data withKeyRef:keyRef];
}

+ (NSData *)decryptData:(NSData *)data withKeyRef:(SecKeyRef) keyRef{
    const uint8_t *srcbuf = (const uint8_t *)[data bytes];
    size_t srclen = (size_t)data.length;
    
    size_t block_size = SecKeyGetBlockSize(keyRef) * sizeof(uint8_t);
    UInt8 *outbuf = malloc(block_size);
    size_t src_block_size = block_size;
    
    NSMutableData *ret = [[NSMutableData alloc] init];
    for(int idx=0; idx<srclen; idx+=src_block_size){
        //NSLog(@"%d/%d block_size: %d", idx, (int)srclen, (int)block_size);
        size_t data_len = srclen - idx;
        if(data_len > src_block_size){
            data_len = src_block_size;
        }
        
        size_t outlen = block_size;
        OSStatus status = noErr;
        status = SecKeyDecrypt(keyRef,
                               kSecPaddingNone,
                               srcbuf + idx,
                               data_len,
                               outbuf,
                               &outlen
                               );
        if (status != 0) {
            NSLog(@"SecKeyEncrypt fail. Error Code: %d", status);
            ret = nil;
            break;
        }else{
            //the actual decrypted data is in the middle, locate it!
            int idxFirstZero = -1;
            int idxNextZero = (int)outlen;
            for ( int i = 0; i < outlen; i++ ) {
                if ( outbuf[i] == 0 ) {
                    if ( idxFirstZero < 0 ) {
                        idxFirstZero = i;
                    } else {
                        idxNextZero = i;
                        break;
                    }
                }
            }
            
            [ret appendBytes:&outbuf[idxFirstZero+1] length:idxNextZero-idxFirstZero-1];
        }
    }
    
    free(outbuf);
    CFRelease(keyRef);
    return ret;
}

+ (NSString *)RSADecryptString:(NSString *)str APIType:(LPAPIType)APIType {
    NSData *data = [[NSData alloc] initWithBase64EncodedString:str options:NSDataBase64DecodingIgnoreUnknownCharacters];
    switch (APIType) {
        case LPAPITypeJAVA: {
            data = [LPRSA RSADecryptData:data publicKey:RSA_KEY_BASE64_JAVA];
            NSString *ret = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            return ret;
        }
            break;
        case LPAPITypePHP: {
            data = [LPRSA RSADecryptData:data publicKey:RSA_KEY_BASE64_PHP];
            NSString *ret = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
            return ret;
        }
            break;
        default:
            return nil;
            break;
    }
}

+ (NSString *)RSADecryptString:(NSString *)str publicKey:(NSString *)pubKey {
    NSData *data = [[NSData alloc] initWithBase64EncodedString:str options:NSDataBase64DecodingIgnoreUnknownCharacters];
    data = [LPRSA RSADecryptData:data publicKey:pubKey];
    NSString *ret = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return ret;
}

@end
