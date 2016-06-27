//
//  MPUKeychain.swift
//  Created by Martin Púčik on 06/27/16.
//

import Security

public class MPUKeychain: NSObject {

    // MARK: - Private
    private class func getKeychainQueryForKey(key: String) -> NSMutableDictionary {
        return (NSMutableDictionary(dictionary: [kSecClass:kSecClassGenericPassword, kSecAttrService:key, kSecAttrAccount:key, kSecAttrAccessible:kSecAttrAccessibleAfterFirstUnlock]).mutableCopy() as! NSMutableDictionary)
    }

    // MARK: - Public

    // MARK: Save
    public class func saveValue(value: AnyObject, forKey key: String) -> Bool {
        let keychainQuery = getKeychainQueryForKey(key)
        deleteValue(forKey: key)
        keychainQuery.setObject(NSKeyedArchiver.archivedDataWithRootObject(value), forKey: kSecValueData as String)
        let result = SecItemAdd(keychainQuery, nil)
        return (result == noErr) ? true:false
    }

    // MARK: Load
    public class func loadValue(forKey key: String) -> AnyObject? {
        let keychainQuery = getKeychainQueryForKey(key)
        keychainQuery.setObject(kCFBooleanTrue, forKey: kSecReturnData as String)
        keychainQuery.setObject(kSecMatchLimitOne, forKey: kSecMatchLimit as String)

        var keyData: AnyObject?
        var value: AnyObject?

        if SecItemCopyMatching(keychainQuery, &keyData) == noErr {
            value = NSKeyedUnarchiver.unarchiveObjectWithData(keyData as! NSData)
            if let value = value {
                return value
            } else {
                return nil
            }
        } else {
            return nil
        }
    }

    // MARK: Delete
    public class func deleteValue(forKey key: String) -> Bool {
        let keychainQuery = getKeychainQueryForKey(key)
        let result = SecItemDelete(keychainQuery)
        return (result == noErr) ? true:false
    }
}
