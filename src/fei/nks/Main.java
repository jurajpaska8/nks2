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

    private void test() throws NoSuchAlgorithmException
    {
        String id = "92318";
        String pin = "000005";
        String pattern = id + pin;
        // reduce hash to pin with 6 numbers
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encodedhash = digest.digest(pattern.getBytes(StandardCharsets.US_ASCII));
        bruteforce(encodedhash);
        System.out.println("end");

        // comparators
        //Comparator<String[]> comparator2 = (o1, o2) -> o1[o1.length - 1].compareTo(o2[o2.length - 1]);
        //Comparator<String[]> comparator3 = Comparator.comparing(o -> o[o.length - 1]);

//        Comparator<String> comparatorLambda = (o1, o2) -> o1.compareTo(o2);
//        Comparator<String> comparatorNaturalOrder = Comparator.naturalOrder();
//        Comparator<String> comparatorMethodReference = String::compareTo;
    }

    // Message digest is not thread safe - needed to use new instance in different threads
    public static void main(String[] args) throws NoSuchAlgorithmException
    {
        String id = "92318";
        // generate 100 random numbers modulo 1 000 000
        List<Integer> generatedValues = generateUniqueNumbersInBase(100, 1_000_000);

        // create starting points
        List<String> startingPoints = prependStringToValues(id, generatedValues);

        // create table
        List<List<String>> table = generateTableFromStarterPoints(startingPoints, 100, id);

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

        // create tree map
        TreeMap<String, String> treeMap = new TreeMap<>();


        // create tree set
        TreeSet<String> treeSet = Arrays
                .stream(arrayTable)
                .map(arr -> arr[arr.length - 1])
                .collect(Collectors.toCollection(TreeSet::new));


        // check if reduced hash from key is endpoint
        String keyToFind = "92318000885";
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashFromKeyToFind = digest.digest(keyToFind.getBytes(StandardCharsets.US_ASCII));
        String reducedHash = reduceHashToNDigitsAndPrependValue(hashFromKeyToFind, 6, id);





        System.out.println("end");

    }
}
