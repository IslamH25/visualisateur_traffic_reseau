Visualisateur de trames  :
HAMI Islam et EL KHADDAR Marwan
2022/2023



###1/ Introduction:

	Ce visualisateur affiche les informations produites par Wireshark dans l’outil 'Flow Graph’.
	Tout d'abord nous crééons un analyseur de trames à partir d'un fichier txt.
	Il comprend :
		- Ethernet (Couche 2)
		- IP (Couche 3)
		- TCP (Couche 4)
		- HTTP (Couche 7)

###2/ Architecture:

		Pour l'architecture du projet nous avons suivi une approche similaire au principe désencapsulation des trames Ethernet à travers diffèrentes classe:

		# La Class Trame.java qui crée l'analyseur de trame et le visualisateur dans 2 fichier .txt differents.

		# La Class TrameReader.java nous permet de manipuler le fichier .txt où se trouve les trame à étudier, en stockant les octets des trames dans des ArrayList
		et résoudre les diffèrentes anomalies.
		
		# La Class TrameHTTP.java permet d'extraire toutes les information qui concerne Http. 

		# La Class TrameTCP.java permet d'extraire toutes les informations qui concerneTCP. 
		  Elle contient les fonctions qui permettent de calculer chaque champs de ce protocole.

		# La Class TrameIP.java permet d'extraire toutes les information qui concerne IP. 
		  
		# La Class TrameEthernet.java permet d'extraire toutes les information qui concerne Ethernet.
		  
		# Le fichier Main.java récupère les informations saisies par l'utilisateur tel le nom du fichier trace
		Puis si les informations saisies par l'utilisateur sont valides, il va faire appelle a la classe TrameReader qui va nettoyer la trame et tester sa validite 
		Si la trame est valide, elle va faire appelle a la classe Trame qui commencera l'analyse de la trame ethernet pour generer des trames ethernet qui seront 
		utilisés pour decoder les champs des couches superieures.
		ce fichier contient aussi un menu de filtre qui apparaitra dans le terminal qui permet de filtrer la liste des trames suivant le filtre saisi
		par l'utilisateur.
		

###3/ Structure du code 
	*Fonctions de nettoyage et validation fichier:
		#readTrame(): lis le fichier Trames.txt ,tester sa validité ,resoudre les differentes anomalies et  d'extraire les octets pour les mettre
		dans des listes.
	*Fonctions de filtrage:
		#affichageFlags(flags) : donne les details des flags TCP
		#afficheOptions(options):calcule les options d'un segment TCP si elles existent
		#affichageProtocol(protocol) : affiche le protocol de la trame IP
		#getTrameList():retourne la liste des ArrayList d'octets des differentes trames.
	*Fonctions d'affichage:
		#ecritureInfos():Ecris dans un fichier Analyse_Trame.txt, toute les informations du decodage de la trames.
		#flowGraph():utilise les informations produite par l'analyseur pour afficher le visualisateur de trame filtrer ou non du flux reseau dans un fichier
		Visualisateur_trame.txt.
	*Fonctions d'analyse:
		#analyseEthernet(trame) : analyse la trame et détermine si le protocole est est IP ou autre puis renvoi les differents champs de l'entete ethernet
		
		#AnalyseIP(trame): analyse la séquence IP et détermine les differents champs de l'entete IP.

		#analyseTCP(trame): analyse la séquence TCP si elle existe et calcule à l'aide de fonctions déjà implémentées les differents champs de l'entete TCP.

		#ecritureInfos(trame ) : analyse l'entete http si elle existe 			

