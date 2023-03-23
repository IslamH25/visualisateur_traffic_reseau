import java.io.*;
import java.awt.Desktop;
import java.util.ArrayList;
import java.util.Scanner;


public class Main {
    public static void main(String[] args) throws FileNotFoundException {
        // On vérifie que le fichier a bien été passé en paramètre
        if (args.length != 1) {
            System.out.println("Il faut donner en paramètre uniquement l'adresse du fichier à lire.\n");
            return;
        }
        File file;
        Boolean fin = false;
        // On crée un TrameReader. On a passé l'adresse du fichier comme paramètre
        TrameReader tr = new TrameReader(args[0]);

        // On lit la (les) trame(s) contenue(s) dans le fichier
        tr.readTrame();

        ArrayList<Trame> tramelist=new ArrayList<>();
        tramelist=tr.getTrameList();
        // On affiche les infos des trames lues
        for (int i = 0; i < tramelist.size(); i++) {
            Trame t = tramelist.get(i);
            t.analyseTrame();
            t.ecritureInfos();
        }
            while (fin==false){
            PrintStream printStream = new PrintStream(new FileOutputStream("Visualisateur_trame.txt"));
        Scanner scanner=new Scanner(System.in);
        System.out.println("                      ----------------------------");
        System.out.println("                     |  VISUALISATEUR DE TRAMES:  |");
        System.out.println("                      ----------------------------");
        System.out.println("Voulez-vous filtrer les trames?");
        System.out.println("1-oui         2-non");
        int choix=scanner.nextInt();
        switch (choix){
            case 1:
                System.out.println("                      ---------------------");
                System.out.println("                     |  CHOIX DU FILTRE:  |");
                System.out.println("                      ---------------------");
                System.out.println("1-Adresse-ip      2-Protocole    3-Flag     4-Port");
                int choix2= scanner.nextInt();
                switch (choix2){
                    case 1:
                        System.out.println("Entrée l'adresse IP de la  machine 1:");
                        String ad1= scanner.next();
                        System.out.println("Entrée l'adresse IP de la  machine 2:");
                        String ad2= scanner.next();
                        for(int i=0;i<tramelist.size();i++){
                            Trame t1=tramelist.get(i);
                            String srcAd = "", desAd = "";
                            for (int j = 0; j < 4; j++) {
                                srcAd += t1.getTrameEthernet().getTrameIP().getSourceAdress()[j];
                                desAd += t1.getTrameEthernet().getTrameIP().getDestinationAdress()[j];
                                if (j != 3) {
                                    srcAd += ".";
                                    desAd += ".";
                                }
                            }
                            if(t1.getTrameEthernet().getType()[1].equals("00") && t1.getTrameEthernet().getTrameIP().getProtocol()==6){
                            if((ad1.equals(srcAd) && ad2.equals(desAd)) || (ad1.equals(desAd) && ad2.equals(srcAd))){
                            t1.flowGraph(printStream);}
                        }}
                        break;
                    case 2:
                        System.out.println("Choisissez le protocole:");
                        System.out.println("1-TCP      2-HTTP");
                        int choix3= scanner.nextInt();
                        switch (choix3){
                            case 1:
                                for(int i=0;i<tramelist.size();i++){
                                    Trame t1=tramelist.get(i);
                                    if(t1.getTrameEthernet().getType()[1].equals("00") && t1.getTrameEthernet().getTrameIP().getProtocol()==6){
                                    if(t1.getTrameEthernet().getTrameIP().getTrameTCP().getHttpTrame()==null){
                                        t1.flowGraph(printStream);}
                                }}
                                break;
                            case 2:
                                for(int i=0;i<tramelist.size();i++){
                                    Trame t1=tramelist.get(i);
                                    if(t1.getTrameEthernet().getType()[1].equals("00") && t1.getTrameEthernet().getTrameIP().getProtocol()==6){
                                    if(t1.getTrameEthernet().getTrameIP().getTrameTCP().getHttpTrame()!=null){
                                        t1.flowGraph(printStream);}
                                }}
                                break;
                        }
                        break;
                    case 3:
                        System.out.println("Choisissez le flag:");
                        System.out.println("1-[SYN]   2-[SYN,ACK]  3-[ACK]   4-[FIN,ACK]  5-[PSH,ACK]");
                        int choix4= scanner.nextInt();
                        switch (choix4){
                            case 1:
                                for(int i=0;i<tramelist.size();i++){
                                    Trame t1=tramelist.get(i);
                                    if(t1.getTrameEthernet().getType()[1].equals("00") && t1.getTrameEthernet().getTrameIP().getProtocol()==6){
                                    if(t1.getTrameEthernet().getTrameIP().getTrameTCP().getSYN()==1 && t1.getTrameEthernet().getTrameIP().getTrameTCP().getFIN()==0 && t1.getTrameEthernet().getTrameIP().getTrameTCP().getACK()==0 ){
                                        t1.flowGraph(printStream);}
                                }}
                                break;
                            case 2:
                                for(int i=0;i<tramelist.size();i++){
                                    Trame t1=tramelist.get(i);
                                    if(t1.getTrameEthernet().getType()[1].equals("00") && t1.getTrameEthernet().getTrameIP().getProtocol()==6){
                                    if(t1.getTrameEthernet().getTrameIP().getTrameTCP().getSYN()==1 && t1.getTrameEthernet().getTrameIP().getTrameTCP().getFIN()==0 && t1.getTrameEthernet().getTrameIP().getTrameTCP().getACK()==1 ){
                                        t1.flowGraph(printStream);}
                                }}
                                break;
                            case 3:
                                for(int i=0;i<tramelist.size();i++){
                                    Trame t1=tramelist.get(i);
                                    if(t1.getTrameEthernet().getType()[1].equals("00") && t1.getTrameEthernet().getTrameIP().getProtocol()==6){
                                    if(t1.getTrameEthernet().getTrameIP().getTrameTCP().getSYN()==0 && t1.getTrameEthernet().getTrameIP().getTrameTCP().getFIN()==0 && t1.getTrameEthernet().getTrameIP().getTrameTCP().getACK()==1 && t1.getTrameEthernet().getTrameIP().getTrameTCP().getPSH()==0 ){
                                        t1.flowGraph(printStream);}
                                }}
                                break;
                            case 4:
                                for(int i=0;i<tramelist.size();i++){
                                    Trame t1=tramelist.get(i);
                                    if(t1.getTrameEthernet().getType()[1].equals("00") && t1.getTrameEthernet().getTrameIP().getProtocol()==6){
                                    if(t1.getTrameEthernet().getTrameIP().getTrameTCP().getSYN()==0 && t1.getTrameEthernet().getTrameIP().getTrameTCP().getFIN()==1 && t1.getTrameEthernet().getTrameIP().getTrameTCP().getACK()==1  ){
                                        t1.flowGraph(printStream);}
                                }}
                                break;
                            case 5:
                                for(int i=0;i<tramelist.size();i++){
                                    Trame t1=tramelist.get(i);
                                    if(t1.getTrameEthernet().getType()[1].equals("00") && t1.getTrameEthernet().getTrameIP().getProtocol()==6){
                                    if(t1.getTrameEthernet().getTrameIP().getTrameTCP().getSYN()==0 && t1.getTrameEthernet().getTrameIP().getTrameTCP().getFIN()==0 && t1.getTrameEthernet().getTrameIP().getTrameTCP().getACK()==1 && t1.getTrameEthernet().getTrameIP().getTrameTCP().getPSH()==1 ){
                                        t1.flowGraph(printStream);}
                                }}
                                break;
                        }
                        break;
                    case 4:
                        System.out.println("Saisissez le port de la machine 1:");
                        int p1=scanner.nextInt();
                        System.out.println("Saisissez le port de la machine 2:");
                        int p2=scanner.nextInt();
                        for(int i=0;i<tramelist.size();i++){
                            Trame t1=tramelist.get(i);
                            if(t1.getTrameEthernet().getType()[1].equals("00") && t1.getTrameEthernet().getTrameIP().getProtocol()==6){
                            if((t1.getTrameEthernet().getTrameIP().getTrameTCP().getSourcePort()==p1 && t1.getTrameEthernet().getTrameIP().getTrameTCP().getDestinationPort()==p2) || (t1.getTrameEthernet().getTrameIP().getTrameTCP().getSourcePort()==p2 && t1.getTrameEthernet().getTrameIP().getTrameTCP().getDestinationPort()==p1 )){
                                t1.flowGraph(printStream);}
                        }}
                        break;

                }
                break;
            case 2:
                for(int i=0;i<tramelist.size();i++){
                    Trame t1=tramelist.get(i);
                    if(t1.getTrameEthernet().getType()[1].equals("00") && t1.getTrameEthernet().getTrameIP().getProtocol()==6)
                        t1.flowGraph(printStream);
                }

        }
        try {
            file = new File("Visualisateur_Trame.txt");
            if (file.createNewFile()) {
            } else {
                file.delete();

                file = new File("Visualisateur_Trame.txt");
            }
        } catch (IOException e) {
            System.out.println("Probleme lors de la création du fichier.");
        }

        System.out.println("voulez vous continuer?");
        System.out.println("1-oui        2-non");
        int y= scanner.nextInt();
        if (y==2){
            fin=true;
        }
        }
        // Ouverture du fichier
        if (Desktop.getDesktop().isSupported(java.awt.Desktop.Action.OPEN)) {
            try {
                java.awt.Desktop.getDesktop().open(new File("Analyse_Trame.txt"));
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
        if (Desktop.getDesktop().isSupported(java.awt.Desktop.Action.OPEN)) {
            try {
                java.awt.Desktop.getDesktop().open(new File("Visualisateur_trame.txt"));
            } catch (IOException ex) {
                ex.printStackTrace();

            }
        }
    }}
