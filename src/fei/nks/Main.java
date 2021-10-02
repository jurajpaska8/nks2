package fei.nks;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class Main
{
    private static String bytesToHex(byte[] hash)
    {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (byte b : hash)
        {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1)
            {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    private static void bruteforce(byte[] hashToFind) throws NoSuchAlgorithmException
    {
        String id = "92318";
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        //String pin = "000000";
        for(int i = 0; i <= 999999; i++)
        {
            String pattern = id + String.format("%06d", i);
            byte[] encodedhash = digest.digest(pattern.getBytes(StandardCharsets.US_ASCII));
            if(Arrays.equals(encodedhash, hashToFind))
            {
                System.out.println("find");
            }
        }
    }

    private static List<Integer> generateUniqueNumbersInBase(int n, int base)
    {
        // generate unique SPs
        ArrayList<Integer> uniqueRandoms = new ArrayList<>();
        Random random = new SecureRandom();
        while (uniqueRandoms.size() < n)
        {
            int tmp = Math.abs(random.nextInt() % base); //1 000 000
            if(!uniqueRandoms.contains(tmp))
                uniqueRandoms.add(tmp);
        }
        return uniqueRandoms;
    }

    private static List<String> prependStringToValues(String prepend, List<Integer> listOfValues)
    {
//        List<String> returnValues = new ArrayList<>();
//        listOfValues.forEach(sp -> returnValues.add(prepend + String.format("%06d",sp)));

        return listOfValues
                .stream()
                .map(sp -> prepend + String.format("%06d",sp))
                .collect(Collectors.toList());
    }

    // another reduction can be base64
    private static String reduceByteToIntMod10(byte b)
    {
        return "" + Math.abs(b % 10);
    }

    private static String reduceHashToNDigitsAndPrependValue(byte[] hash, int n, String prepend)
    {
        StringBuilder toReturn = new StringBuilder();
        for (int i = 0; i < n; i++)
        {
            toReturn.append(reduceByteToIntMod10(hash[i]));
        }
        return prepend + toReturn;
    }

    private static List<String> generateLineFromStarterPoint(MessageDigest digest, String starterPoint, int t, String id)
    {
        List<String> line = new ArrayList<>();
        line.add(starterPoint);

        for(int i = 1; i <= t; i++)
        {
            byte[] hash = digest.digest(line.get(i - 1).getBytes(StandardCharsets.US_ASCII));
            line.add(reduceHashToNDigitsAndPrependValue(hash, 6, id));
        }
        return line;
    }

    private static List<List<String>> generateTableFromStarterPoints(List<String> starterPoints, int t, String id) throws NoSuchAlgorithmException
    {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return starterPoints
                .stream()
                .map(sp -> generateLineFromStarterPoint(digest, sp, t, id))
                .collect(Collectors.toList());
    }

    private static boolean isReducedHashInTreeMap(String reducedHash, TreeMap<String, String> map)
    {
        return map.containsKey(reducedHash);
    }


    private static void tryAllEntries(byte[] hash, TreeMap<String, String> map, int t, int n, String id) throws NoSuchAlgorithmException
    {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        String reducedHash = null;
        boolean found = false;
        int reductions = 0;
        for(int i = 0; i < t; i++)
        {
            reducedHash = reduceHashToNDigitsAndPrependValue(hash, n, id);
            reductions = i + 1;
            if(isReducedHashInTreeMap(reducedHash, map))
            {
                System.out.println("Key: " + reducedHash + ", retrieved after :" + reductions + " reductions is endpoint");
                System.out.println("Searched Key is :" + reductions + " cols on the left from endpoint: " + reducedHash);
                found = true;
                break;
            }
            hash = digest.digest(reducedHash.getBytes(StandardCharsets.US_ASCII));
        }

        if(found)
        {
            // find starting point
            String sp = map.get(reducedHash);
            int numOfEncAndRed = t - reductions;
            for(int i = 0; i < numOfEncAndRed; i++)
            {
                byte[] h = digest.digest(sp.getBytes(StandardCharsets.US_ASCII));
                sp = reduceHashToNDigitsAndPrependValue(h, 6, id);
            }
            System.out.println(sp);
        }
    }

    /**
     *
     * Generates sorted hellman table of possible keys. It is sorted by endpoints (last element of each row)
     *
     * */
    private static String[][] createTable(int m, int t, String id, int baseOfPIN) throws NoSuchAlgorithmException
    {
        // generate m random numbers modulo baseOfPIN
        List<Integer> generatedValues = generateUniqueNumbersInBase(m, baseOfPIN);

        // create starting points: every key is in form ID+PIN
        List<String> startingPoints = prependStringToValues(id, generatedValues);

        // create table - m rows * t cols
        List<List<String>> table = generateTableFromStarterPoints(startingPoints, t, id);

        // to array
        String[][] arrayTable = table.stream()
                .map(l -> l.toArray(new String[0]))
                .toArray(String[][]::new);

        // sort array based on last element - EP
        Comparator<String[]> comparator = new Comparator<String[]>() {
            @Override
            public int compare(String[] o1, String[] o2)
            {
                return o1[o1.length - 1].compareTo(o2[o2.length - 1]);
            }
        };
        Arrays.sort(arrayTable, comparator);
        return arrayTable;
    }

    /**
     * Final treeMap contains key-value pairs : (Endpoint, StartPoint). Sorted by keys (Endpoints)
     * */
    private static TreeMap<String, String> createTreeMap(String[][] arrayTable)
    {
        TreeMap<String, String> treeMap = new TreeMap<>();
        Arrays.stream(arrayTable)
                .forEach(arr -> treeMap.put(arr[arr.length - 1], arr[0]));
        return treeMap;
    }

    // Message digest is not thread safe - needed to use new instance in different threads
    public static void main(String[] args) throws NoSuchAlgorithmException
    {
        String id = "92318";
        int baseOfPin = 1_000_000;
        int numberOfDigitsInPin = 6;
        // rows
        int m = 100;
        // cols
        int t = 100;

        // create table
        String[][] arrayTable = createTable(m, t, id, baseOfPin);

        // create tree map
        TreeMap<String, String> treeMap = createTreeMap(arrayTable);


        // test if image of key[2][96] is equal to key[2][97]
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        String keyToFind = arrayTable[2][99];
        byte[] hashFromKeyToFind = digest.digest(keyToFind.getBytes(StandardCharsets.US_ASCII));
        String check = arrayTable[2][97];
        String reducedHash = reduceHashToNDigitsAndPrependValue(hashFromKeyToFind, numberOfDigitsInPin, id);

        // try to find key from hash in table
        System.out.println("Searching for key: " + keyToFind);
        tryAllEntries(hashFromKeyToFind, treeMap, t, numberOfDigitsInPin, id);

        System.out.println("end");

    }
}
