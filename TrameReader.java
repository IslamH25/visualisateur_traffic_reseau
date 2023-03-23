import java.io.File; // Import the File class
import java.io.FileNotFoundException; // Import this class to handle errors
import java.util.ArrayList;
import java.util.Scanner; // Import the Scanner class to read text files

public class TrameReader {
    // Attributs
    private File file;
    private ArrayList<Trame> trameList;

    // Constructeur
    public TrameReader(String filename) {
        this.file = new File(filename);
        this.trameList = new ArrayList<Trame>();
    }

    // Methodes
    public void readTrame() {
        // On lit le fichier
        try {
            System.out.println("On commence la lecture de la trame.\n");

            Scanner sc = new Scanner(file);

            int lineNumber = 1;

            // Création de trame avancée
            Trame trame = null;
            int trameExistence = 0;

            while (sc.hasNextLine()) {
                String line = sc.nextLine();
                String[] lineTab = line.split("   ");
                if(lineTab[0].equals("")){
                    continue;}
                String[] lineTab2= lineTab[1].split(" ");
                int checkValue = 0; // Valeur permettant de savoir si il ya un probleme dans la ligne
                
                // Vérification de l'offset
                String octet = lineTab[0];

                if (isNotHexa(octet) == 1) {
                    checkValue = 1;
                    System.out.println("ATTENTION - La ligne " + lineNumber + " ne sera pas prise en compte.\n");
                }
                else {
                    try {
                        int val = Integer.parseInt(octet, 16);
    
                        // On vérifie si on doit créer une nouvelle trame ou pas
                        if (val == 0) {
                            trame = new Trame();
                            trameList.add(trame);
    
                            trameExistence = 1;
                        }
    
                        // On vérifie que l'offset est conforme
                        if (trameExistence == 1) {
                            if (val != trame.getLength()) checkValue = 1;
                        }
    
                    } catch (NumberFormatException e) {
                        checkValue = 1;
                        System.out.println("ATTENTION - L'offset " + octet + " ne correspond pas à la ligne " + lineNumber + "\n");
                    }
                }

                // Lecture des octets
                if ((checkValue != 1) && (trameExistence == 1)) {
                    ArrayList<String> newPart = new ArrayList<String>();
                    int endOfLine = 1;

                    for (int i = 0; i < lineTab2.length; i++) {
                        
                        if (isNotHexa(lineTab2[i]) == 1) {
                            for (int j = i; j < lineTab2.length; j++) {
                                if (isNotHexa(lineTab2[j]) == 0 && lineTab2[j].length() == 2) {
                                    System.out.println("Il y a une erreur à la ligne " + lineNumber + ". Erreur : " + lineTab[i] + "\n");

                                    endOfLine = 0;
                                    checkValue = 1;
                                    break;
                                }
                            }
                        }
                        else if (checkValue == 0) newPart.add(lineTab2[i]);
                        
                        if (endOfLine == 0) break;
                    }

                    if (checkValue != 1) {
                        trame.addTrameBytes(newPart);
                    }
                }
                
                lineNumber++;
            }

            sc.close();

        } catch (FileNotFoundException e) {
            System.out.println("Fichier non trouvé. Vérifier le répertoire.\n");
        }
    }

    // Accesseurs
    public ArrayList<Trame> getTrameList() {
        return trameList;
    }

    public File getFile() {
        return file;
    }

    // Méthodes
    public void toStringTrames(int valParLigne) {
        for (int i = 0; i < trameList.size(); i++) {
            Trame t = trameList.get(i);
            System.out.println("Nombre d'octets lus dans la trame " + t.getID() + " - " + t.getLength() + "\n");
            System.out.println(t.toString(16) + "\n");
        }
    }

    public int isNotHexa(String text) {
        int ret = 0;

        try {
            Integer.parseInt(text, 16);
        } catch (NumberFormatException e) {
            ret = 1;
        }

        return ret;
    }
}