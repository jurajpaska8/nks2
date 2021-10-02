package fei.nks;

import jdk.internal.util.xml.impl.Pair;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class Main
{

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
        return listOfValues
                .stream()
                .map(sp -> prepend + String.format("%06d",sp))
                .collect(Collectors.toList());
    }

    private static List<String> nRandomKeys(int n, int base, String id)
    {
        List<Integer> ints = generateUniqueNumbersInBase(n, base);
        return prependStringToValues(id, ints);
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

    /**
     * Returns number of applied reductions in order to find pattern, or 0, if pater was not found.
     * */
    private static List<ReductionsEndpointPair> tryAllEntries(byte[] hash, TreeMap<String, String> map, int t, int n, String id) throws NoSuchAlgorithmException
    {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        String reducedHash;
        List<ReductionsEndpointPair> listOfPairs = new ArrayList<>();
        int reductions;
        for(int i = 0; i < t; i++)
        {
            reducedHash = reduceHashToNDigitsAndPrependValue(hash, n, id);
            reductions = i + 1;
            if(isReducedHashInTreeMap(reducedHash, map))
            {
                ReductionsEndpointPair rp = new ReductionsEndpointPair(reductions, reducedHash);
                listOfPairs.add(rp);
            }
            hash = digest.digest(reducedHash.getBytes(StandardCharsets.US_ASCII));
        }
        return listOfPairs;
    }

    private static String returnWantedKey(TreeMap<String, String> map, ReductionsEndpointPair pair, int t,  MessageDigest digest, String id)
    {
        String tmpKey = map.get(pair.endpoint);
        int numOfEncAndRed = t - pair.reductions;
        for(int i = 0; i < numOfEncAndRed; i++)
        {
            byte[] h = digest.digest(tmpKey.getBytes(StandardCharsets.US_ASCII));
            tmpKey = reduceHashToNDigitsAndPrependValue(h, 6, id);
        }
        return tmpKey;
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

    private static void test100lines100columns1000values() throws NoSuchAlgorithmException
    {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        int keysToTryCount = 1_000;
        int base = 1_000_000;
        int numberOfDigitsInPin = 6;
        int m = 100;
        int t = 100;
        String id = "92318";

        // create table
        String[][] arrayTable = createTable(m, t, id, base);

        // create tree map
        TreeMap<String, String> treeMap = createTreeMap(arrayTable);

        // create random values
        List<String> randomKeys = nRandomKeys(keysToTryCount, base, id);
        List<byte[]> hashesFromRandomKeys = randomKeys
                .stream()
                .map(k -> digest.digest(k.getBytes(StandardCharsets.US_ASCII)))
                .collect(Collectors.toList());

        List<String> retrievedKeysFromHashesHellman = new ArrayList<>();
        for(byte[] hash : hashesFromRandomKeys)
        {
            List<ReductionsEndpointPair> pairs = tryAllEntries(hash, treeMap, t, numberOfDigitsInPin, id);
            if(pairs.size() > 0)
            {
                String tmp = "";
                for(ReductionsEndpointPair pair : pairs)
                {
                    String wantedKey = returnWantedKey(treeMap, pair, t, digest, id);
                    //System.out.println(wantedKey + " found");
                    if(Arrays.equals(digest.digest(wantedKey.getBytes(StandardCharsets.US_ASCII)), hash))
                    {
                        tmp = wantedKey;
                        break;
                    }
                }
                retrievedKeysFromHashesHellman.add(tmp);

            }
            else
            {
                //System.out.println("Not Found");
                retrievedKeysFromHashesHellman.add("");
            }
        }

        long numberOfNonEmptyValues = retrievedKeysFromHashesHellman.stream().filter(k -> k.length() > 0).count();
        long numberOfEqualKeys = 0;
        for(int i = 0; i < retrievedKeysFromHashesHellman.size(); i++)
        {
            if(retrievedKeysFromHashesHellman.get(i).equals(randomKeys.get(i)))
                numberOfEqualKeys++;
        }

        // check
        int numberOfKeysIncludedInArrayTableAndInRandomValues = 0;
        for(String str : randomKeys)
        {
            boolean found = false;
            for(String[] arr : arrayTable)
            {
                if(found) break;
                for(String tmp : arr)
                {
                    if(tmp.equals(str))
                    {
                        numberOfKeysIncludedInArrayTableAndInRandomValues++;
                        found = true;
                        break;
                    }
                }
            }
        }

    }

    // Message digest is not thread safe - needed to use new instance in different threads
    public static void main(String[] args) throws NoSuchAlgorithmException
    {
//        String id = "92318";
//        int baseOfPin = 1_000_000;
//        int numberOfDigitsInPin = 6;
//        // rows
//        int m = 100;
//        // cols
//        int t = 100;
//
//        // create table
//        String[][] arrayTable = createTable(m, t, id, baseOfPin);
//
//        // create tree map
//        TreeMap<String, String> treeMap = createTreeMap(arrayTable);
//
//
//        // test if image of key[2][96] is equal to key[2][97]
//        MessageDigest digest = MessageDigest.getInstance("SHA-256");
//        String keyToFind = arrayTable[2][99];
//        byte[] hashFromKeyToFind = digest.digest(keyToFind.getBytes(StandardCharsets.US_ASCII));
//        String check = arrayTable[2][97];
//        String reducedHash = reduceHashToNDigitsAndPrependValue(hashFromKeyToFind, numberOfDigitsInPin, id);
//
//        // try to find key from hash in table
//        System.out.println("Searching for key: " + keyToFind);
//        ReductionsEndpointPair pair = tryAllEntries(hashFromKeyToFind, treeMap, t, numberOfDigitsInPin, id);
//        if(pair.reductions != -1)
//        {
//            String wantedKey = returnWantedKey(treeMap, pair, t, digest, id);
//            System.out.println(wantedKey + " found");
//        }

        test100lines100columns1000values();
        System.out.println("end");

    }
}
