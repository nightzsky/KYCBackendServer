import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.json.JSONObject;

/**
 * Class which registers a user for the KYC service
 */
public class UserRegisterKYC {
    String name;
    String id;
    String dob;
    String postalCode;

    public UserRegisterKYC(String name, String id, String dob, String postalCode) {
        this.name = name;
        this.id = id;
        this.dob = dob;
        this.postalCode = postalCode;
    }

    public int sendRegisterRequest(){
        HttpURLConnection urlConnection = null;

        try {
            URL url = new URL("https://kyc-project.herokuapp.com/register_kyc");
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("name",this.name);
            jsonObject.put("postal_code", this.postalCode);
            jsonObject.put("id_number", this.id);
            jsonObject.put("dob",this.dob);

            JSONObject encryptedJSON = EncryptRequest.encryptRequest(jsonObject);

            urlConnection = (HttpURLConnection) url.openConnection();
            //set the request method to Post
            urlConnection.setRequestMethod("POST");
            urlConnection.setRequestProperty("Content-Type","application/json");
            String encoded = Base64.getEncoder().encodeToString(("admin"+":"+"secret").getBytes(StandardCharsets.UTF_8));  //Java 8
            urlConnection.setRequestProperty("Authorization", "Basic "+encoded);
            urlConnection.setDoInput(true);
            urlConnection.setDoOutput(true);


            //output the stream to the server
            OutputStreamWriter wr = new OutputStreamWriter(urlConnection.
                    getOutputStream());
            wr.write(encryptedJSON.toString());
            wr.flush();

            int responseCode = urlConnection.getResponseCode();
            return responseCode;
        }catch (Exception ex){
            ex.printStackTrace();
            return 0;
        }
    }
}


