/*
 * Zsdes.java
 *
 * Created on November 14, 2008, 6:26 PM
 * @version 1.0
 * @author Constantine Kyriakopoulos, zfox@users.sourceforge.net
 * License: GNU GPL v2
 */

package zsdes;

/**
 * Provides the back-end functionality of the app. All methods facilitating encryption, decryption
 * and key generation, reside here. It's the Zsdes library for usage by the front end.
 */
public class Zsdes
{
    //  Constant fields describing the predefined permutations
    static public final int[] P10 = {3, 5, 2, 7, 4, 10, 1, 9, 8, 6};
    static public final int[] P08 = {6, 3, 7, 4, 8, 5, 10, 9};
    static public final int[] P04 = {2, 4, 3, 1};
    static public final int[] IP = {2, 6, 3, 1, 4, 8, 5, 7};
    static public final int[] IP_1 = {4, 1, 3, 5, 7, 2, 8, 6};
    static public final int[] E_P = {4, 1, 2, 3, 2, 3, 4, 1};

    //  Matrices (S-Boxes) facilitating the fk function
    static public final int[][] s0 = {{1, 0, 3, 2}, {3, 2, 1, 0}, {0, 2, 1, 3}, {3, 1, 3, 2}};
    static public final int[][] s1 = {{0, 1, 2, 3}, {2, 0, 1, 3}, {3, 0, 1, 0}, {2, 1, 0, 3}};

    /**
     * Encrypts the given ciphertext
     * @param key The 10-bit encryption key in binary
     * @param plainText The 8-bit text to encrypt in binary
     * @param encLog Text buffer to put encryption process info
     * @param keyLog Text buffer to put key-generation process info
     * @return Guess what. The cipher text.
     */
    static public int[] encrypt(int[] key, final int[] plainText, StringBuffer encLog, StringBuffer keyLog)
    {
        encLog.append("Encrypting..." + "\n");
        encLog.append("Plaintext: " + byIntArray(plainText) + "\n");
        encLog.append("With key: " + byIntArray(key) + "\n");

        int[] ipPlainText = permute(plainText, IP);
        encLog.append("Permuting plaintext with IP: " + byIntArray(ipPlainText) + "\n");
        int[] mL = leftHalf(ipPlainText);
        int[] mR = rightHalf(ipPlainText);
        encLog.append("Left half of the result: " + byIntArray(mL) + "\n");
        encLog.append("Right half of result: " + byIntArray(mR) + "\n");

        int[] keyA = generateKeyA(key, keyLog);
        encLog.append("Generated Subkey A: " + byIntArray(keyA) + "\n");

        int[] epMR = permute(mR, E_P);
        encLog.append("Permuting 2nd half with E/P: " + byIntArray(epMR) + "\n");
        int[] sFull = xor(keyA, epMR);
        encLog.append("XOR of " + byIntArray(epMR) + " with Subkey A: " + byIntArray(sFull) + "\n");
        encLog.append("Left half: " + byIntArray(leftHalf(sFull)) + " is used to get the index from matrix S0" + "\n");
        encLog.append("Right half: " + byIntArray(rightHalf(sFull)) + " is used to get the index from matrix S1" + "\n");
        int indexA = s0[getRow(leftHalf(sFull))][getColumn(leftHalf(sFull))];
        int indexB = s1[getRow(rightHalf(sFull))][getColumn(rightHalf(sFull))];
        encLog.append("Index of S0: " + indexA + "\n");
        encLog.append("Index of S1: " + indexB + "\n");
        int[] m_r = getBinArray(indexA, indexB);
        encLog.append("Merged indices into binary: " + byIntArray(m_r) + "\n");

        int[] p04mr = permute(m_r, P04);
        encLog.append("Permuting the result with P04: " + byIntArray(p04mr) + "\n");
        int[] p04mrml = xor(p04mr, mL);
        encLog.append("XOR of " + byIntArray(p04mr) + " with " + byIntArray(mL) + ": " + byIntArray(p04mrml) + "\n");
        int[] mplus = swap(p04mrml, mR);
        encLog.append("Swapping/merging " + byIntArray(p04mrml) + " and " + byIntArray(mR) + ": " + byIntArray(mplus) + "\n");
        int[] x1 = leftHalf(mplus);
        int[] x2 = rightHalf(mplus);
        encLog.append("First half: " + byIntArray(x1) + "\n");
        encLog.append("Second half: " + byIntArray(x2) + "\n");

        int[] keyB = generateKeyB(key, keyLog);
        encLog.append("Generated Subkey B: " + byIntArray(keyB) + "\n");

        int[] perX2EP = permute(x2, E_P);
        encLog.append("Permuting " + byIntArray(x2) + " with E/P: " + byIntArray(perX2EP) + "\n");
        int[] kFull = xor(perX2EP, keyB);
        encLog.append("XOR of " + byIntArray(perX2EP) + " with Subkey B: " + byIntArray(kFull) + "\n");
        encLog.append("Left half: " + byIntArray(leftHalf(kFull)) + " is used to get the index of matrix S0" + "\n");
        encLog.append("Right half: " + byIntArray(rightHalf(kFull)) + " is used to get the index of matrix S1" + "\n");
        int indexAA = s0[getRow(leftHalf(kFull))][getColumn(leftHalf(kFull))];
        int indexBB = s1[getRow(rightHalf(kFull))][getColumn(rightHalf(kFull))];
        encLog.append("Index of S0: " + indexAA + "\n");
        encLog.append("Index of S1: " + indexBB + "\n");
        int[] m_r2 = getBinArray(indexAA, indexBB);
        encLog.append("Merged indices into binary: " + byIntArray(m_r2) + "\n");

        int[] mr2p04 = permute(m_r2, P04);
        encLog.append("Permuting " + byIntArray(m_r2) + " with P04: " + byIntArray(mr2p04) + "\n");
        int[] mr2p04x1 = xor(mr2p04, x1);
        encLog.append("XOR of " + byIntArray(mr2p04) + " with " + byIntArray(x1) + ": " + byIntArray(mr2p04x1) + "\n");
        int[] xx = merge(mr2p04x1, x2);
        encLog.append("Merging " + byIntArray(mr2p04x1) + " with " + byIntArray(x2) + ": " + byIntArray(xx) + "\n");
        encLog.append("Inverse permutation (IP-1) of " + byIntArray(xx) + "\n");
        int[] cipherText = permute(xx, IP_1);
        encLog.append("Ciphertext generated successfully: ");
        encLog.append(byIntArray(cipherText) + "\n");

        return cipherText;
    }

    /**
     * Decrypts the given ciphertext
     * @param key The 10-bit encryption key in binary
     * @param cipherText The 8-bit text to decrypt in binary
     * @param decLog Text buffer to put decryption process info
     * @param keyLog Text buffer to put key-generation process info
     * @return Guess what. The plaintext.
     */
    public static int[] decrypt(int[] key, int[] cipherText, StringBuffer decLog, StringBuffer keyLog)
    {
        decLog.append("Decrypting..." + "\n");
        decLog.append("Ciphertext: " + byIntArray(cipherText) + "\n");
        decLog.append("With key: " + byIntArray(key) + "\n");

        int[] ipText = permute(cipherText, IP);
        decLog.append("Permuting " + byIntArray(cipherText) + " with IP: " + byIntArray(ipText) + "\n");
        int[] ipTextLeft = leftHalf(ipText);
        int[] ipTextRight = rightHalf(ipText);
        decLog.append("First half: " + byIntArray(ipTextLeft) + "\n");
        decLog.append("Second half: " + byIntArray(ipTextRight) + "\n");

        int[] epText = permute(ipTextRight, E_P);
        decLog.append("Permuting " + byIntArray(ipTextRight) + " with E/P: " + byIntArray(epText) + "\n");

        int[] keyB = generateKeyB(key, keyLog);
        decLog.append("Generated Subkey B: " + byIntArray(keyB) + "\n");

        int[] ztemp = xor(epText, keyB);
        decLog.append("XOR of " + byIntArray(epText) + " with Subkey B: " + byIntArray(ztemp) + "\n");
        decLog.append("Left half: " + byIntArray(leftHalf(ztemp)) + " is used to get the index of matrix S0" + "\n");
        decLog.append("Right half: " + byIntArray(rightHalf(ztemp)) + " is used to get the index of matrix S1" + "\n");
        int indexA = s0[getRow(leftHalf(ztemp))][getColumn(leftHalf(ztemp))];
        int indexB = s1[getRow(rightHalf(ztemp))][getColumn(rightHalf(ztemp))];
        decLog.append("Index of S0: " + indexA + "\n");
        decLog.append("Index of S1: " + indexB + "\n");
        int[] mx = getBinArray(indexA, indexB);
        decLog.append("Merged indices into binary: " + byIntArray(mx) + "\n");

        int[] p04Text = permute(mx, P04);
        decLog.append("Permuting " + byIntArray(mx) + " with P04: " + byIntArray(p04Text) + "\n");
        int[] xoredP04 = xor(p04Text, ipTextLeft);
        decLog.append("XOR of " + byIntArray(p04Text) + " with " + byIntArray(ipTextLeft) + ": " + byIntArray(xoredP04) + "\n");
        int[] blue = merge(xoredP04, ipTextRight);
        decLog.append("Merging " + byIntArray(xoredP04) + " with " + byIntArray(ipTextRight) + ": " + byIntArray(blue) + "\n");

        int[] green = swap(leftHalf(blue), rightHalf(blue));
        decLog.append("First half: " + byIntArray(leftHalf(blue)) + "\n");
        decLog.append("Second half: " + byIntArray(rightHalf(blue)) + "\n");
        decLog.append("Swapping/merging both parts: " + byIntArray(green) + "\n");

        int[] rightHEP = permute(rightHalf(green), E_P);
        decLog.append("Permuting the right half of " + byIntArray(green) + " with E/P: " + byIntArray(rightHEP) + "\n");
        int[] keyA = generateKeyA(key, keyLog);
        decLog.append("Generated Subkey A: " + byIntArray(keyA) + "\n");
        int[] ztemp2 = xor(rightHEP, keyA);
        decLog.append("XOR of " + byIntArray(rightHEP) + " with Subkey A: " + byIntArray(ztemp2) + "\n");
        decLog.append("Left half: " + byIntArray(leftHalf(ztemp2)) + " is used to get the index of matrix S0" + "\n");
        decLog.append("Right half: " + byIntArray(rightHalf(ztemp2)) + " is used to get the index of matrix S1" + "\n");
        int indexAA = s0[getRow(leftHalf(ztemp2))][getColumn(leftHalf(ztemp2))];
        int indexBB = s1[getRow(rightHalf(ztemp2))][getColumn(rightHalf(ztemp2))];
        decLog.append("Index of S0: " + indexAA + "\n");
        decLog.append("Index of S1: " + indexBB + "\n");
        int[] mx2 = getBinArray(indexAA, indexBB);
        decLog.append("Merged indices into binary: " + byIntArray(mx2) + "\n");

        int[] mx2PerP04 = permute(mx2, P04);
        decLog.append("Permuting " + byIntArray(mx2) + " with P04: " + byIntArray(mx2PerP04) + "\n");
        int[] lHGreen = leftHalf(green);
        decLog.append("Using first half of " + byIntArray(green) + ": " + byIntArray(lHGreen) + "\n");
        int[] xorTemp = xor(mx2PerP04, lHGreen);
        decLog.append("XOR of " + byIntArray(mx2PerP04) + " with " + byIntArray(lHGreen) + ": " + byIntArray(xorTemp) + "\n");
        int[] rHGreen = rightHalf(green);
        decLog.append("Using second half of " + byIntArray(green) + ": " + byIntArray(rHGreen) + "\n");
        int[] merged = merge(xorTemp, rHGreen);
        decLog.append("Merging " + byIntArray(xorTemp) + " with " + byIntArray(rHGreen) + ": " + byIntArray(merged) + "\n");

        decLog.append("Inverse permutation (IP-1) of " + byIntArray(merged) + "\n");
        int[] plainText = permute(merged, IP_1);
        decLog.append("Plaintext generated successfully: ");
        decLog.append(byIntArray(plainText) + "\n");

        return plainText;
    }

    /**
     * Generates the first subkey
     * @param key The 10-bit encryption key
     * @param log Text buffer to put key-generation process info
     * @return The first subkey
     */
    static public int[] generateKeyA(final int[] key, StringBuffer log)
    {
        log.append("Main Key: " + byIntArray(key) + "\n");
        log.append("Generating Subkey A...\n");

        int[] kplus = generateKeyPlus(key, log);
        log.append("Permuting " + byIntArray(kplus) + " with P08..." + "\n");
        int[] keyA = permute(kplus, P08);
        log.append("Subkey A generated successfully: ");
        for(int i = 0; i < keyA.length; ++i)
            log.append(keyA[i]);
        log.append("\n\n");

        return keyA;
    }

    /**
     * Generates the second subkey
     * @param key The 10-bit encryption key
     * @param log Text buffer to put key-generation process info
     * @return The second subkey
     */
    static public int[] generateKeyB(final int[] key, StringBuffer log)
    {
        log.append("Main Key: " + byIntArray(key) + "\n");
        log.append("Generating Subkey B...\n");

        int[] kplus = generateKeyPlus(key, log);
        int[] keyPlusLeft = leftHalf(kplus);
        int[] keyPlusRight = rightHalf(kplus);

        keyPlusLeft = shiftLeft(shiftLeft(keyPlusLeft));
        keyPlusRight = shiftLeft(shiftLeft(keyPlusRight));
        log.append("First part shifted 2 places left: ");
        log.append(byIntArray(keyPlusLeft) + '\n');
        log.append("Second part shifted 2 places left: ");
        log.append(byIntArray(keyPlusRight) + '\n');

        int[] kplusplus = merge(keyPlusLeft, keyPlusRight);
        log.append("Parts merged: ");
        log.append(byIntArray(kplusplus) + '\n');

        log.append("Permuting merged result with P08..." + "\n");
        int[] keyB = permute(kplusplus, P08);
        log.append("Subkey B generated successfully: ");
        log.append(byIntArray(keyB) + "\n\n");

        return keyB;
    }

    /**
     * Common functionality to both subkey generation
     * @param key The encryption key
     * @param log Text buffer to put key-generation process info
     * @return Intermediate subkey-generation result
     */
    static private int[] generateKeyPlus(final int[] key, StringBuffer log)
    {
        log.append("Permuting key: " + byIntArray(key) + "\n");
        int[] keyP10 = permute(key, P10);
        log.append("Key after P10 permutation: ");
        log.append(byIntArray(keyP10) + '\n');

        int[] keyP10Left = leftHalf(keyP10);
        int[] keyP10Right = rightHalf(keyP10);
        log.append("First part: ");
        log.append(byIntArray(keyP10Left) + '\n');
        log.append("Second part: ");
        log.append(byIntArray(keyP10Right) + '\n');

        keyP10Left = shiftLeft(keyP10Left);
        keyP10Right = shiftLeft(keyP10Right);

        log.append("First part shifted 1 place left: ");
        log.append(byIntArray(keyP10Left) + '\n');
        log.append("Second part shifted 1 place left: ");
        log.append(byIntArray(keyP10Right) + '\n');

        int[] kplus = merge(keyP10Left, keyP10Right);
        log.append("Parts merged: ");
        log.append(byIntArray(kplus) + '\n');

        return kplus;
    }

    /**
     * Permutes the given bit array according to the indices. For example, if the first place of indices
     * contains the 3 value, resulting array at its first place will contain the value of the third place.
     * @param data Actual data to permute
     * @param indices Array of indices to use to perform the permutation
     * @return Permuted array of bits
     */
    static private int[] permute(final int[] data, final int[] indices)
    {
        int[] result = new int[indices.length];

        for(int i = 0; i < result.length; ++i)
            result[i] = data[indices[i] - 1];

        return result;
    }

    /**
     * Shifts one place left all data bits. The initial first bit is put in last place.
     * @param data Array bits to shift left
     * @return Resulting bit array
     */
    static private int[] shiftLeft(final int[] data)
    {
        int tempVal = data[0];
        int[] result = new int[data.length];

        for(int i = 1; i < data.length; ++i)
            result[i - 1] = data[i];

        result[result.length - 1] = tempVal;
        return result;
    }

    /**
     * Performs Exclusive OR between the corresponding places of the two input arrays.
     * @param lhs Left-hand size array
     * @param rhs Right-hand side array
     * @return Result of the operation
     */
    static private int[] xor(int[] lhs, int[] rhs)
    {
        if(lhs.length != rhs.length) return null;

        int[] result = new int[lhs.length];

        for(int i = 0; i < lhs.length; ++i)
            result[i] = (lhs[i] != rhs[i]) ? 1 : 0;

        return result;
    }

    /**
     * Returns the left part of the input array.
     * @param data Input array
     * @return Left half of the input array
     */
    private static int[] leftHalf(final int[] data)
    {
        int[] leftHalf = new int[data.length / 2];

        for(int i = 0; i < data.length; ++i)
            if(i < data.length / 2) {
                leftHalf[i] = data[i];
            }
            else {
                break;
            }

        return leftHalf;
    }

    /**
     * Returns the right part of the input array.
     * @param data Input array
     * @return Right half of the input array
     */
    private static int[] rightHalf(final int[] data)
    {
        int[] rightHalf = new int[data.length / 2];

        for(int i = data.length / 2; i < data.length; ++i)
            rightHalf[i - data.length / 2] = data[i];

        return rightHalf;
    }

    /**
     * Returns the matrix row in decimal denoted by the first and last bits combined.
     * @param data Input array
     * @return Row in decimal
     */
    private static int getRow(final int[] data)
    {
        if(data[0] == 0 && data[3] == 0) return 0;
        if(data[0] == 0 && data[3] == 1) return 1;
        if(data[0] == 1 && data[3] == 0) return 2;
        if(data[0] == 1 && data[3] == 1) return 3;

        return 0;
    }

    /**
     * Returns the matrix column in decimal denoted by the second and third bits combined.
     * @param data Input array
     * @return Column in decimal
     */
    private static int getColumn(final int[] data)
    {
        if(data[1] == 0 && data[2] == 0) return 0;
        if(data[1] == 0 && data[2] == 1) return 1;
        if(data[1] == 1 && data[2] == 0) return 2;
        if(data[1] == 1 && data[2] == 1) return 3;

        return 0;
    }

    /**
     * Converts the decimal 2-digit input number into a binary representation.
     * @param a First decimal number
     * @param b Second decimal number
     * @return Binary representation
     */
    static private int[] getBinArray(int a, int b)
    {
        int[] result = new int[4];

        if(a == 0 && b == 0) {
            result[0] = 0;
            result[1] = 0;
            result[2] = 0;
            result[3] = 0;
        }

        if(a == 0 && b == 1) {
            result[0] = 0;
            result[1] = 0;
            result[2] = 0;
            result[3] = 1;
        }

        if(a == 0 && b == 2) {
            result[0] = 0;
            result[1] = 0;
            result[2] = 1;
            result[3] = 0;
        }

        if(a == 0 && b == 3) {
            result[0] = 0;
            result[1] = 0;
            result[2] = 1;
            result[3] = 1;
        }

        if(a == 1 && b == 0) {
            result[0] = 0;
            result[1] = 1;
            result[2] = 0;
            result[3] = 0;
        }

        if(a == 1 && b == 1) {
            result[0] = 0;
            result[1] = 1;
            result[2] = 0;
            result[3] = 1;
        }

        if(a == 1 && b == 2) {
            result[0] = 0;
            result[1] = 1;
            result[2] = 1;
            result[3] = 0;
        }

        if(a == 1 && b == 3) {
            result[0] = 0;
            result[1] = 1;
            result[2] = 1;
            result[3] = 1;
        }

        if(a == 2 && b == 0) {
            result[0] = 1;
            result[1] = 0;
            result[2] = 0;
            result[3] = 0;
        }

        if(a == 2 && b == 1) {
            result[0] = 1;
            result[1] = 0;
            result[2] = 0;
            result[3] = 1;
        }

        if(a == 2 && b == 2) {
            result[0] = 1;
            result[1] = 0;
            result[2] = 1;
            result[3] = 0;
        }

        if(a == 2 && b == 3) {
            result[0] = 1;
            result[1] = 0;
            result[2] = 1;
            result[3] = 1;
        }

        if(a == 3 && b == 0) {
            result[0] = 1;
            result[1] = 1;
            result[2] = 0;
            result[3] = 0;
        }

        if(a == 3 && b == 1) {
            result[0] = 1;
            result[1] = 1;
            result[2] = 0;
            result[3] = 1;
        }

        if(a == 3 && b == 2) {
            result[0] = 1;
            result[1] = 1;
            result[2] = 1;
            result[3] = 0;
        }

        if(a == 3 && b == 3) {
            result[0] = 1;
            result[1] = 1;
            result[2] = 1;
            result[3] = 1;
        }

        return result;
    }

    /**
     * Swaps the two parts. Results in one array.
     * @param lhs Left part of the array
     * @param rhs Right part of the array
     * @return Resulting swapped array
     */
    static private int[] swap(int[] lhs, int[] rhs)
    {
        int[] result = new int[lhs.length + rhs.length];

        for(int i = 0; i < result.length; ++i) {
            if(i < rhs.length) {
                result[i] = rhs[i];
            }
            else {
                result[i] = lhs[i - lhs.length];
            }
        }

        return result;
    }

    /**
     * Merges the two input arrays in one.
     * @param lhs First input
     * @param rhs Second input array
     * @return Merged array
     */
    static private int[] merge(int[] lhs, int[] rhs)
    {
        int[] result = new int[lhs.length + rhs.length];
        for(int i = 0; i < result.length; ++i) {
            if(i < lhs.length) {
                result[i] = lhs[i];
            }
            else {
                result[i] = rhs[i - rhs.length];
            }
        }

        return result;
    }

    /**
     * Converts an integer array to String.
     * @param data Input array
     * @return String representation of the input data
     */
    static public String byIntArray(int[] data)
    {
        StringBuffer buf = new StringBuffer();
        for(int i = 0; i < data.length; ++i)
            buf.append(data[i]);
        return buf.toString();
    }
}
