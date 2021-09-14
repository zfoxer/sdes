/*
 * Zsdes.java
 *
 * Created on November 14, 2008, 6:26 PM
 * @version 0.9
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
        encLog.append("Plaintext: ");
        encLog.append(byIntArray(plainText) + "\n");

        int[] ipPlainText = permute(plainText, IP);
        encLog.append("I/Permutation: ");
        encLog.append(byIntArray(ipPlainText) + "\n");

        int[] mL = leftHalf(ipPlainText);
        int[] mR = rightHalf(ipPlainText);

        int[] keyA = generateKeyA(key, keyLog);
        int[] epMR = permute(mR, E_P);
        encLog.append("E/Permutation from 2nd half: ");
        encLog.append(byIntArray(epMR) + "\n");

        int[] sFull = xor(keyA, epMR);

        int indexA = s0[getRow(leftHalf(sFull))][getColumn(leftHalf(sFull))];
        int indexB = s1[getRow(rightHalf(sFull))][getColumn(rightHalf(sFull))];

        int[] m_r = getBinArray(indexA, indexB);
        int[] p04mr = permute(m_r, P04);
        int[] p04mrml = xor(p04mr, mL);

        int[] mplus = swap(xor(p04mr, mL), mR);
        encLog.append("Middle result: ");
        encLog.append(byIntArray(mplus) + "\n");

        int[] x1 = leftHalf(mplus);
        int[] x2 = rightHalf(mplus);

        int[] kFull = xor(permute(x2, E_P), generateKeyB(key, keyLog));

        int indexAA = s0[getRow(leftHalf(kFull))][getColumn(leftHalf(kFull))];
        int indexBB = s1[getRow(rightHalf(kFull))][getColumn(rightHalf(kFull))];
        int[] m_r2 = getBinArray(indexAA, indexBB);

        int[] xx = merge(xor(permute(m_r2, P04), x1), x2);
        encLog.append("IP_1 permutation of: ");
        encLog.append(byIntArray(xx) + "\n");
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
        decLog.append("Ciphertext: ");
        decLog.append(byIntArray(cipherText) + "\n");

        int[] ipText = permute(cipherText, IP);
        decLog.append("I/Permutation: ");
        decLog.append(byIntArray(ipText) + "\n");

        int[] ipTextLeft = leftHalf(ipText);
        int[] ipTextRight = rightHalf(ipText);

        decLog.append("E/Permutation: ");
        decLog.append(byIntArray(permute(ipTextRight, E_P)) + "\n");
        int[] ztemp = xor(permute(ipTextRight, E_P), generateKeyB(key, keyLog));
        int indexA = s0[getRow(leftHalf(ztemp))][getColumn(leftHalf(ztemp))];
        int indexB = s1[getRow(rightHalf(ztemp))][getColumn(rightHalf(ztemp))];
        int[] mx = getBinArray(indexA, indexB);

        decLog.append("P04 permutation of middle result: ");
        decLog.append(byIntArray(mx) + "\n");
        int[] blue = merge(xor(permute(mx, P04), ipTextLeft), ipTextRight);
        int[] green = swap(leftHalf(blue), rightHalf(blue));

        decLog.append("E/Permutation of: ");
        decLog.append(byIntArray(rightHalf(green)) + "\n");
        int[] ztemp2 = xor(permute(rightHalf(green), E_P), generateKeyA(key, keyLog));
        int indexAA = s0[getRow(leftHalf(ztemp2))][getColumn(leftHalf(ztemp2))];
        int indexBB = s1[getRow(rightHalf(ztemp2))][getColumn(rightHalf(ztemp2))];
        int[] mx2 = getBinArray(indexAA, indexBB);

        decLog.append("Final P04 permutation of: ");
        decLog.append(byIntArray(mx2) + "\n");
        int[] plainText = permute(merge(xor(permute(mx2, P04), leftHalf(green)), rightHalf(green)), IP_1);
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
        log.append("Generating KeyA...\n");

        int[] kplus = generateKeyPlus(key, log);
        int[] keyA = permute(kplus, P08);
        log.append("KeyA generated successfully: ");
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
        log.append("Generating KeyB...\n");
        int[] kplus = generateKeyPlus(key, log);

        int[] keyPlusLeft = leftHalf(kplus);
        int[] keyPlusRight = rightHalf(kplus);
        log.append("First part of the key: ");
        log.append(byIntArray(keyPlusLeft) + '\n');
        log.append("Second part of the key: ");
        log.append(byIntArray(keyPlusRight) + '\n');

        keyPlusLeft = shiftLeft(shiftLeft(keyPlusLeft));
        keyPlusRight = shiftLeft(shiftLeft(keyPlusRight));
        log.append("First part shifted 2 places left: ");
        log.append(byIntArray(keyPlusLeft) + '\n');
        log.append("Second part shifted 2 places left: ");
        log.append(byIntArray(keyPlusRight) + '\n');

        int[] kplusplus = merge(keyPlusLeft, keyPlusRight);
        log.append("Keys merged: ");
        log.append(byIntArray(kplusplus) + '\n');

        log.append("Permuting with P08...\n");
        int[] keyB = permute(kplusplus, P08);
        log.append("KeyB generated successfully: ");
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
        int[] keyP10 = permute(key, P10);
        log.append("Key after P10 permutation: ");
        log.append(byIntArray(keyP10) + '\n');

        int[] keyP10Left = leftHalf(keyP10);
        int[] keyP10Right = rightHalf(keyP10);
        log.append("First part of the key: ");
        log.append(byIntArray(keyP10Left) + '\n');
        log.append("Second part of the key: ");
        log.append(byIntArray(keyP10Right) + '\n');

        keyP10Left = shiftLeft(keyP10Left);
        keyP10Right = shiftLeft(keyP10Right);

        log.append("First part shifted 1 place left: ");
        log.append(byIntArray(keyP10Left) + '\n');
        log.append("Second part shifted 1 place left: ");
        log.append(byIntArray(keyP10Right) + '\n');

        int[] kplus = merge(keyP10Left, keyP10Right);
        log.append("Keys merged: ");
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
