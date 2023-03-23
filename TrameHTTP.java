import java.util.ArrayList;

import java.io.File;  // Import the File class
import java.io.IOException;  // Import the IOException class to handle errors
import java.io.FileWriter;

public class TrameHTTP {
    // Attributs
    private File file;

    private ArrayList<String> data;
    private String requete;
    // Constructeur
    public TrameHTTP(ArrayList<String> data, File file) {
        this.data = data;
        this.file = file;
    }

    // Ecriture
    public void ecritureInfos() {
        try {

            FileWriter fileWriter = new FileWriter(file, true);
            requete="";
            char valRetour = '\n';
            // Trame HTTP
            fileWriter.write("\nHypertext Transfer Protocol\n\t");
            for (int i = 0; i < data.size(); i++) {
                int val = Integer.parseInt(data.get(i), 16);
                char c = (char)val;
                fileWriter.write(Character.toString(c));
                    if(val!=10 && val!=13){
                    requete+=Character.toString(c);}else{
                        requete+='\t';
                    }


                char valData = (char)Integer.parseInt(data.get(i), 16);

                if (valRetour == valData) {
                    fileWriter.write("\t");
            }
            }

            fileWriter.close();
        }
        catch (IOException e) {
            System.out.println("Erreur lors de l'écriture");
            e.printStackTrace();
        }
    }

    public String getRequete() {
        return requete;
    }
}
