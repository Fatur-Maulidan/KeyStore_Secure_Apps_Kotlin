package com.example.myapplication

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.security.keystore.KeyProperties

import android.security.keystore.KeyGenParameterSpec
import javax.crypto.KeyGenerator
import android.widget.TextView
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.ObjectOutputStream
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec


class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)


        setContentView(R.layout.activity_main)
        val dataToEncrypt = "Hello World"

        val test: TextView = findViewById(R.id.test)
        val test2: TextView = findViewById(R.id.test2)

        val cryptoManager = KeyStore()

        val bytes = dataToEncrypt.encodeToByteArray()
        val file = File(filesDir, "secret.txt")
        if(!file.exists()){
            file.createNewFile()
        }
        val fos = FileOutputStream(file)

        val messageToEncrypt = cryptoManager.encrypt(
            bytes = bytes,
            outputStream = fos
        ).decodeToString()

        val messageToDecrypt = cryptoManager.decrypt(
            inputStream = FileInputStream(file)
        ).decodeToString()

        test2.text = messageToEncrypt
        test.text = messageToDecrypt

//        test.text = keyStore.encryptData(dataToEncrypt)
//        test2.text = keyStore.decryptData(test.text.toString())

//        try {
//            val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
//            keyGenerator.init(
//                KeyGenParameterSpec.Builder(
//                    "TestDoang",
//                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
//                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
//                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
//                    .setRandomizedEncryptionRequired(false)
//                    .build())
//            val key = keyGenerator.generateKey()
//            val cipher = Cipher.getInstance("${KeyProperties.KEY_ALGORITHM_AES}/CBC/PKCS7Padding")
//            cipher.init(Cipher.ENCRYPT_MODE, key)
//            val encryptedData = cipher.doFinal(dataToEncrypt.toByteArray(Charsets.UTF_8))
//
//
//            val inputStream = resources.openRawResource(R.raw.private_key)
//            val yakin = inputStream.bufferedReader().use { it.readText() }
//            val keystore = KeyStore.getInstance("PKCS12")
//            keystore.load(inputStream, yakin.toCharArray())
//
//            val privateKeyEntry = keystore.getEntry("my_private_key_alias", null) as KeyStore.PrivateKeyEntry
//            val privateKey = privateKeyEntry.privateKey
//            val keyStore = KeyStore.getInstance("AndroidKeyStore")
//            keyStore.load(null)
//
//            val cipherDecrypt = Cipher.getInstance("${KeyProperties.KEY_ALGORITHM_AES}/CBC/PKCS7Padding")
//            cipherDecrypt.init(Cipher.DECRYPT_MODE, privateKey)
//            val decryptedData = cipherDecrypt.doFinal(encryptedData)



//// Generate key AES dan simpan ke dalam keystore TestDoang
//            val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
//            val keyGenParameterSpec = KeyGenParameterSpec.Builder(
//                "Del",
//                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
//                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
//                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
//                .setRandomizedEncryptionRequired(false)
//                .build()
//            keyGenerator.init(keyGenParameterSpec)
//            keyGenerator.generateKey()

//            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

// Enkripsi data dengan menggunakan kunci AES yang telah disimpan dalam keystore TestDoang
//            val cipher = Cipher.getInstance("${KeyProperties.KEY_ALGORITHM_AES}/CBC/PKCS7Padding")
//            val key = keyStore.getKey("TestDoang", null) as SecretKey
//            cipher.init(Cipher.ENCRYPT_MODE, key)
//            val encryptedData = cipher.doFinal("Data rahasia yang akan dienkripsi".toByteArray())
//
//            val outputStream = FileOutputStream("F:\\School\\Polban\\Teknik Komputer dan Informatika\\Matkul\\Semester 4\\WS\\Proyek 4\\Learn\\Key\\private_key")
//            outputStream.write(encryptedData)
//            outputStream.close()

//// Simpan kunci enkripsi AES ke dalam file private_key.ppek
//            val privateKey = keyStore.getKey("TestDoang", null) as SecretKey
//            cipher.init(Cipher.DECRYPT_MODE, privateKey, encryptedData)
//            val inputStream = FileInputStream(File(applicationContext.filesDir, "F:\\School\\Polban\\Teknik Komputer dan Informatika\\Matkul\\Semester 4\\WS\\Proyek 4\\Learn\\Key\\private_key"))
//            val decryptedData = cipher.doFinal(encryptedData)
//            val decryptedString = String(decryptedData)
//        } catch (e: Exception) {
//            test.text = "error"
//        }



    }
}