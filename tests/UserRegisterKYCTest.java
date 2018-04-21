import org.junit.Test;

import java.util.Random;

import static org.junit.Assert.*;

/**
 * Class which tests the registration process for the KYC service
 * The bulk of the testing is to ensure that invalid requests are not accepted
 */
public class UserRegisterKYCTest {
    String validId = "INSERT VALID SG ID HERE";
    String validId2 = "INSERT VALID SG ID HERE";
    String validId3 = "INSERT VALID SG ID HERE";
    @Test
    public void testCorrectRegistration(){
        UserRegisterKYC userRegister = new UserRegisterKYC("hello",validId,"26/02/1995","738583");
        int requestResponse = userRegister.sendRegisterRequest();
        assertEquals(200, requestResponse);
    }

    /**
     * Test that ensures repeat registrations are not accepted
     */
    @Test
    public void testRepeatRegistration(){
        UserRegisterKYC userRegister = new UserRegisterKYC("hello", validId2, "26/02/1995","738583");
        int requestResponse = userRegister.sendRegisterRequest();
        requestResponse = userRegister.sendRegisterRequest();
        assertEquals(500,requestResponse);
    }

    /**
     * Test that incorrect names will be rejected by the system
     * Incorrect names include names with numbers or symbols
     * Both are tested here
     */
    @Test
    public void testIncorrectName(){
        UserRegisterKYC nameWithNumber = new UserRegisterKYC("hello123",validId3,"26/02/1995","738583");
        int requestResponse = nameWithNumber.sendRegisterRequest();
        assertEquals(400, requestResponse);

        UserRegisterKYC nameWithSymbol = new UserRegisterKYC("hello!", validId3, "26/02/1995","587631");
        requestResponse = nameWithSymbol.sendRegisterRequest();
        assertEquals(400, requestResponse);
    }

    /**
     * Test that incorrect IDs will be rejected by the system
     * IDs can be incorrect if they contain non-alphanumeric characters, do not have a valid prefix (S,T,F or G),
     * if the middle are not all numbers, have an incorrect length, or if they do not fulfill the checksum for Singaporean IDs
     * All possible failure cases are tested here
     */
    @Test
    public void testIncorrectId(){
        UserRegisterKYC idTooLong = new UserRegisterKYC("hello","S12345678B","26/02/1995","738583");
        int requestResponse = idTooLong.sendRegisterRequest();
        assertEquals(400, requestResponse);

        UserRegisterKYC nonAlphanumId = new UserRegisterKYC("hello","S12345!8B","26/02/1995","738583");
        requestResponse = nonAlphanumId.sendRegisterRequest();
        assertEquals(400,requestResponse);

        UserRegisterKYC invalidPrefixId = new UserRegisterKYC("hello","A"+validId3.substring(1),"26/02/1995","738583");
        requestResponse = invalidPrefixId.sendRegisterRequest();
        assertEquals(400,requestResponse);

        UserRegisterKYC alphaInMiddleId = new UserRegisterKYC("hello","S1234A68B","26/02/1995","738583");
        requestResponse = alphaInMiddleId.sendRegisterRequest();
        assertEquals(400,requestResponse);

        UserRegisterKYC idTooShort = new UserRegisterKYC("hello","S123678B","26/02/1995","738583");
        requestResponse = idTooShort.sendRegisterRequest();
        assertEquals(400,requestResponse);

        UserRegisterKYC invalidChecksum = new UserRegisterKYC("hello","S1234578B","26/02/1995","738583");
        requestResponse = invalidChecksum.sendRegisterRequest();
        assertEquals(400,requestResponse);

    }

    /**
     * Test that all incorrect dates will be rejected by the system
     * Incorrect dates include wrong format(not dd/mm/yyyy), characters other than numbers and /, month exceeding 12,
     * dates exceeding the number of days in the month, and dates exceeding the current date
     */
    @Test
    public void testIncorrectDate(){
        UserRegisterKYC feb29NonLeap = new UserRegisterKYC("hello",validId3,"29/02/1995","738583");
        int requestResponse = feb29NonLeap.sendRegisterRequest();
        assertEquals(400,requestResponse);

        UserRegisterKYC feb30Leap = new UserRegisterKYC("hello",validId3,"30/02/1996","738583");
        requestResponse = feb30Leap.sendRegisterRequest();
        assertEquals(400,requestResponse);

        UserRegisterKYC longMonth32 = new UserRegisterKYC("hello",validId3,"32/01/1995","738583");
        requestResponse = longMonth32.sendRegisterRequest();
        assertEquals(400,requestResponse);

        UserRegisterKYC shortMonth31 = new UserRegisterKYC("hello",validId3,"31/04/1995","738583");
        requestResponse = shortMonth31.sendRegisterRequest();
        assertEquals(400,requestResponse);

        UserRegisterKYC wrongSeparator = new UserRegisterKYC("hello",validId3,"28.02.1995","738583");
        requestResponse = wrongSeparator.sendRegisterRequest();
        assertEquals(400,requestResponse);

        UserRegisterKYC wrongDateLength = new UserRegisterKYC("hello",validId3,"9/02/1995","738583");
        requestResponse = wrongDateLength.sendRegisterRequest();
        assertEquals(400,requestResponse);

        UserRegisterKYC wrongMonthLength = new UserRegisterKYC("hello",validId3,"27/2/1995","738583");
        requestResponse = wrongMonthLength.sendRegisterRequest();
        assertEquals(400,requestResponse);

        UserRegisterKYC wrongYearLength = new UserRegisterKYC("hello",validId3,"27/02/195","738583");
        requestResponse = wrongYearLength.sendRegisterRequest();
        assertEquals(400,requestResponse);

        UserRegisterKYC moreThan12Months = new UserRegisterKYC("hello",validId3,"15/13/1995","738583");
        requestResponse = moreThan12Months.sendRegisterRequest();
        assertEquals(400,requestResponse);

        UserRegisterKYC dateInFuture = new UserRegisterKYC("hello",validId3,"29/03/2020","738583");
        requestResponse = feb30Leap.sendRegisterRequest();
        assertEquals(400,requestResponse);
    }

    /**
     * Test that all incorrect postal codes will be rejected by the system
     * Postal codes are rejected if they start with 74 or 82-99, if they are not of length 6, or contain non-digits
     */
    @Test
    public void testIncorrectPostalCode(){
        UserRegisterKYC tooLong = new UserRegisterKYC("hello",validId3,"30/03/1995","7385483");
        int requestResponse = tooLong.sendRegisterRequest();
        assertEquals(400,requestResponse);

        UserRegisterKYC tooShort = new UserRegisterKYC("hello", validId3, "30/03/1995", "48532");
        requestResponse = tooShort.sendRegisterRequest();
        assertEquals(400,requestResponse);

        UserRegisterKYC startWith74 = new UserRegisterKYC("hello", validId3, "30/03/1995", "746532");
        requestResponse = startWith74.sendRegisterRequest();
        assertEquals(400,requestResponse);

        UserRegisterKYC startWithMoreThan82 = new UserRegisterKYC("hello", validId3, "30/03/1995", "967532");
        requestResponse = startWithMoreThan82.sendRegisterRequest();
        assertEquals(400,requestResponse);
    }

    // Robustness test that uses a lot of random inputs and ensures that the system does not accept these requests
    @Test
    public void testRobustnessRegisterKyc(){
        for (int i = 0; i < 100; i++){
            UserRegisterKYC userRegisterKyc = new UserRegisterKYC(RandomInput.randomString(), RandomInput.randomString(), RandomInput.randomString(), RandomInput.randomString());
            int requestResponse = userRegisterKyc.sendRegisterRequest();
            assertFalse(requestResponse==200);
        }
    }

}
