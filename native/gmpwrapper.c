#include <stdlib.h>
#include <jni.h>
#include <gmp.h>

#include "gmpwrapper.h"

JNIEXPORT jstring JNICALL Java_ch_csnc_burp_jwtscanner_Gmp_sub(JNIEnv *env, jobject obj, jstring a, jstring b) {
    // Convert Java strings to C strings
    const char *aStr = (*env)->GetStringUTFChars(env, a, 0);
    const char *bStr = (*env)->GetStringUTFChars(env, b, 0);

    // Initialize GMP variables
    mpz_t aNum, bNum, result;
    mpz_init(aNum);
    mpz_init(bNum);
    mpz_init(result);

    // Set the values of a and b
    mpz_set_str(aNum, aStr, 10);
    mpz_set_str(bNum, bStr, 10);

    // Perform subtraction
    mpz_sub(result, aNum, bNum);

    // Convert result to string
    char *resultStr = mpz_get_str(NULL, 10, result);

    // Release resources
    (*env)->ReleaseStringUTFChars(env, a, aStr);
    (*env)->ReleaseStringUTFChars(env, b, bStr);
    mpz_clear(aNum);
    mpz_clear(bNum);
    mpz_clear(result);

    // Create a new Java string to return
    jstring jResult = (*env)->NewStringUTF(env, resultStr);
    free(resultStr); // Free the result string allocated by GMP

    return jResult;
}

JNIEXPORT jstring JNICALL Java_ch_csnc_burp_jwtscanner_Gmp_cdiv(JNIEnv *env, jobject obj, jstring a, jstring b) {
    // Convert Java strings to C strings
    const char *aStr = (*env)->GetStringUTFChars(env, a, 0);
    const char *bStr = (*env)->GetStringUTFChars(env, b, 0);

    // Initialize GMP variables
    mpz_t aNum, bNum, quotient, remainder;
    mpz_init(aNum);
    mpz_init(bNum);
    mpz_init(quotient);
    mpz_init(remainder);

    // Set the values of a and b
    mpz_set_str(aNum, aStr, 10);
    mpz_set_str(bNum, bStr, 10);

    // Perform division
    mpz_cdiv_qr(quotient, remainder, aNum, bNum);

    // Convert quotient to string
    char *resultStr = mpz_get_str(NULL, 10, quotient);

    // Release resources
    (*env)->ReleaseStringUTFChars(env, a, aStr);
    (*env)->ReleaseStringUTFChars(env, b, bStr);
    mpz_clear(aNum);
    mpz_clear(bNum);
    mpz_clear(quotient);
    mpz_clear(remainder);

    // Create a new Java string to return
    jstring jResult = (*env)->NewStringUTF(env, resultStr);
    free(resultStr); // Free the result string allocated by GMP

    return jResult;
}

JNIEXPORT jstring JNICALL Java_ch_csnc_burp_jwtscanner_Gmp_pow(JNIEnv *env, jobject obj, jstring base, jstring exp) {
    const char *baseStr = (*env)->GetStringUTFChars(env, base, 0);
    const char *expStr = (*env)->GetStringUTFChars(env, exp, 0);

    mpz_t baseNum, expNum, result;
    mpz_init(baseNum);
    mpz_init(expNum);
    mpz_init(result);

    mpz_set_str(baseNum, baseStr, 10);
    mpz_set_str(expNum, expStr, 10);
    mpz_pow_ui(result, baseNum, mpz_get_ui(expNum));

    char *resultStr = mpz_get_str(NULL, 10, result);

    (*env)->ReleaseStringUTFChars(env, base, baseStr);
    (*env)->ReleaseStringUTFChars(env, exp, expStr);
    mpz_clear(baseNum);
    mpz_clear(expNum);
    mpz_clear(result);

    jstring jResult = (*env)->NewStringUTF(env, resultStr);
    free(resultStr);
    return jResult;
}

JNIEXPORT jstring JNICALL Java_ch_csnc_burp_jwtscanner_Gmp_powm(JNIEnv *env, jobject obj, jstring base, jstring exp, jstring mod) {
    const char *baseStr = (*env)->GetStringUTFChars(env, base, 0);
    const char *expStr = (*env)->GetStringUTFChars(env, exp, 0);
    const char *modStr = (*env)->GetStringUTFChars(env, mod, 0);

    mpz_t baseNum, expNum, modNum, result;
    mpz_init(baseNum);
    mpz_init(expNum);
    mpz_init(modNum);
    mpz_init(result);

    mpz_set_str(baseNum, baseStr, 10);
    mpz_set_str(expNum, expStr, 10);
    mpz_set_str(modNum, modStr, 10);
    mpz_powm(result, baseNum, expNum, modNum);

    char *resultStr = mpz_get_str(NULL, 10, result);

    (*env)->ReleaseStringUTFChars(env, base, baseStr);
    (*env)->ReleaseStringUTFChars(env, exp, expStr);
    (*env)->ReleaseStringUTFChars(env, mod, modStr);
    mpz_clear(baseNum);
    mpz_clear(expNum);
    mpz_clear(modNum);
    mpz_clear(result);

    jstring jResult = (*env)->NewStringUTF(env, resultStr);
    free(resultStr);
    return jResult;
}

JNIEXPORT jstring JNICALL Java_ch_csnc_burp_jwtscanner_Gmp_gcd(JNIEnv *env, jobject obj, jstring a, jstring b) {
    // Convert Java strings to C strings
    const char *aStr = (*env)->GetStringUTFChars(env, a, 0);
    const char *bStr = (*env)->GetStringUTFChars(env, b, 0);

    // Initialize GMP variables
    mpz_t aNum, bNum, result;
    mpz_init(aNum);
    mpz_init(bNum);
    mpz_init(result);

    // Set the values of a and b
    mpz_set_str(aNum, aStr, 10);
    mpz_set_str(bNum, bStr, 10);

    // Calculate GCD
    mpz_gcd(result, aNum, bNum);

    // Convert result to string
    char *resultStr = mpz_get_str(NULL, 10, result);

    // Release resources
    (*env)->ReleaseStringUTFChars(env, a, aStr);
    (*env)->ReleaseStringUTFChars(env, b, bStr);
    mpz_clear(aNum);
    mpz_clear(bNum);
    mpz_clear(result);

    // Create a new Java string to return
    jstring jResult = (*env)->NewStringUTF(env, resultStr);
    free(resultStr); // Free the result string allocated by GMP

    return jResult;
}
