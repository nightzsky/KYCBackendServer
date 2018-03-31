import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
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

    public static void main(String[] args) {
        UserRegisterKYC userRegister = new UserRegisterKYC("hello","S9503226E","26/01/1995","738583");
        System.out.println(userRegister.sendRegisterRequest());
        UserRegisterKYC userRegister1 = new UserRegisterKYC("hello","S1316428B","26/01/1995","738583");
        System.out.println(userRegister1.sendRegisterRequest());
        UserRegisterKYC userRegister2 = new UserRegisterKYC("hello","S1393715Z","26/01/1995","738583");
        System.out.println(userRegister2.sendRegisterRequest());
    }

}


