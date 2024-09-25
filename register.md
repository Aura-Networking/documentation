# Registerter


# Objectif

Nous devons créer un utilisateur et le mettre dans la base de données. Il est nécessaire de faire en sorte de récupérer les données envoyées du front, les traiter et les comparer pour créer un utilisateur ou renvoyer une erreur.


## Réalisation

Nous devons lire l'objet JSON envoyé par le front et vérifié que tout est en l'ordre. 
Il est essentiel de décoder du JSON et de le mettre dans une structure go. Ce qui permettra de vérifier la concordance des deux mots de passe, le format de celui-ci et s'il y'a des zones vides dans les parties obligatoires : mail, mot de passe, prénom, nom de famille et date de naissance.
Si tout est en ordre nous créons un UID et cryptons le mot de passe. Il faudra également vérifier si l'email est utilisé par un autre utilisateur dans la DB. 
Ensuite les données sont insérées dans deux tables différentes. Une qui contient les informations de base et une pour l'authentification.
Enfin nous devons envoyé la réponse au front tout en générant un JWT avec la table AUTH.


## Conception


Nous devons recréer une structure pour ajouter une méthode et lire le body de la requête.
```go
nw := model.ResponseWriter{
	ResponseWriter: w,
}

body, _ := io.ReadAll(r.Body)
defer r.Body.Close()
```


Décoder le JSON en une structure en GO, une pour l'authentification l'autre pour les autres informations.
```go
var register model.Register
json.Unmarshal(body, &register)
json.Unmarshal(body, &register.Auth)
```


Ensuite nous vérifions avec la fonction importée si tous les champs obligatoires sont remplis correctement.
```go
if err := utils.RegisterVerification(register); err != nil {
	nw.Error(err.Error())
	log.Printf("[%s] [Register] %s", r.RemoteAddr, err.Error())
	return
}
```


La fonction RegisterVerification assure que les conditions pour s’inscrire sont réunies. Voir les commentaires //.
```go
func RegisterVerification(register model.Register) error {

// Vérifie si le mot de passe et sa confirmation correspondent
	if register.Auth.Password != register.Auth.ConfirmPassword {
		return errors.New("password and password confirmation do not match")
	}

// Vérifie que le mot de passe est puissant selon nos critères
	if !IsValidPassword(register.Auth.Password) {
		return errors.New("incorrect password ! the password must contain    characters, 1 uppercase letter, 1 special character, 1 number")
	}

// Vérifie que les champs obligatoires ne sont pas vides
	if register.Auth.Email == "" || register.Auth.Password == "" || register.FirstName == "" || register.LastName == "" || register.BirthDate == "" {
		return errors.New("there is an empty field")
	}

return nil
}
```


Une autre fonction est appelée et crée un UID et crypte le mot de passe.
```go
if err := utils.CreateUuidAndCrypt(&register); err != nil {
	nw.Error(err.Error())
	log.Printf("[%s] [Register] %s", r.RemoteAddr, err.Error())
	return
}
```
Les fonctionnalités des  bibliothèques uuid et crypto sont utilisées, voir les commentaires //.

##### Ancre Bcrypt

```go
func CreateUuidAndCrypt(register *model.Register) error {


// Le mot de passe est haché avec un "cost" de 12, qui définit le nombre de fois qu'il est haché. Le coût n'est pas le maximum, mais il est suffisant pour garantir une sécurité adéquate tout en restant performant.

// Le hachage avec bcrypt utilise un "sel", une donnée aléatoire ajoutée avant le hachage. Cela garantit que le hachage d'un même mot de passe ne génère pas le même haché.

// Il est important de ne pas stocker le mot de passe en clair pour des raisons de sécurité.

	cryptedPassword, err :=
	bcrypt.GenerateFromPassword([]byte(register.Auth.Password), 12)
	if err != nil {
		return errors.New("there is a probleme with bcrypt")
	}
	register.Auth.Password = string(cryptedPassword)


// Un nouvel identifiant unique appelé UUID (Universally Unique Identifier) est créé pour dissocier chaque utilisateur. 

// La version 7 est une norme récente qui combine des caractéristiques temporelles et aléatoires. Cette version est particulièrement utile dans les systèmes nécessitant une séquence temporelle des événements tout en maintenant une haute unicité grâce à des composants aléatoires intégrés.


// Composition UUID V7 : 0x01e0b4a2-1a58-7e0b-9d12-3456789abcdef 
// 0x01e0b4a2** : Horodatage en millisecondes (représenté en hexadécimal).
// 1a58 : Composant aléatoire.
// 7e0b : Identifie la version du UUID (ici, v7).
// 9d12 : Composant aléatoire supplémentaire.
// 456789abcdef : Dernière partie aléatoire.


	uuid, err := uuid.NewV7()
	if err != nil {
		return errors.New("there is a probleme with the generation of the uuid")
	}
	register.Auth.Id = uuid.String()
	return nil
}
```

##### Fin Ancre Bcrypt


Il nous faut également manipuler la DB pour vérifier si le mail est déja utilisé par un autre utilisateur :
```go

// SelectFromDb est appelé et permet de vérifier si le mail est présent dans Auth
authData, err := utils.SelectFromDb("Auth", db, map[string]any{"Email": register.Auth.Email})
if err != nil {
	nw.Error("Internal error: Problem during database query: " + err.Error())
	log.Printf("[%s] [Register] %s", r.RemoteAddr, err.Error())
	return
}

  
// Si c'est différent de 0, c'est que le mail est déja utilisé un message d'erreur est envoyé
// Il est à preciser que l'UUID et le mot de passe crypté etant stocké dans la structure qui est elle même dans la fonction principale, le return fera en sorte d'oublier ces informations
if len(authData) != 0 {
	nw.Error("Email is already used")
	log.Printf("[%s] [Register] %s", r.RemoteAddr, "Email is already used")
	return
}
```



##### Ancre Select
La fonction qui a été importé permet de faire des requêtes SQL à n'importe quel table. Mais aussi les représenter sous une forme facile à manipuler en Go, c'est-à-dire comme un slice de maps où chaque map représente une ligne de la table avec des noms de colonnes comme clés.
```go
func SelectFromDb(tabelName string, db *sql.DB, Args map[string]any) ([]map[string]any, error) {
	// Prépare la requête et le résultat en appelant la fonction PrepareStmt
	column, rows, err := PrepareStmt(tabelName, db, Args)
	if err != nil {
		return nil, err
	}

  
	// Iinitialisation de la strucuture du résultat
	// Le any est important car notre fonctione principale est fléxible ce qui permet de traité des données de différentes type dans notre data base
	var result []map[string]any



	// Chaque ligne du résultat est parcourue avec Next, car celui-ci retourne true tant qu'il reste des lignes à parcourir dans la requête SQL.
	
	for rows.Next() {
		// On initialise une map dans laquelle nous allons ajouter les valeurs ainsi que le nom des colonne
		row := make(map[string]any)
		
		// On initialise et on alloue de l'espace mémoire pour le tableau d'interface qui va stocker temporairement les valeurs obtenues pour la ligne actuelle
		values := make([]interface{}, len(column))
		for i := 0; i < len(column); i++ {
			values[i] = new(string)
		}

		// On stocke les valeurs obtenues pour la ligne actuel dans le tableau d'interface
		if err := rows.Scan(values...); err != nil {
			return nil, err
		}

		// On remplie la map avec en clé le nom de la colonne et en valeur la value obtenu par la requête
		for i, v := range column {
			row[v] = values[i]
		}

		// On ajoute la map qui vient d'être remplie dans le tableau de map
		result = append(result, row)
	}

return result, nil
}
```
La fonction PrepareStmt appelé  dans SelectFromDb, elle génère et exécute une fonction SQL. 
```go


// La fonction prends le nom de la table auquel on veut agir
// Elle est directement lié à notre db
// Args est une map qui contient les collones des tables en clés 
func PrepareStmt(tabelName string, db *sql.DB, Args map[string]any) ([]string, *sql.Rows, error) {

  
	// La variable whereClauses variable stocke les conditions les conditions de notre requête.
	// Params lui contient et remplace la valeur de notre "?" 
	var whereClauses []string
	var params []any


	// Ici on récupère notre valeur de manière sécuriser en évitant les injections
	// Exemple, la requête `age = ?`, au lieu de remplacer ? par 30, notre valeur est stocké dans params, lors de l'exécution ? sera remplacé par params. Les valeurs ne sont pas directement insérées dans la requête SQL, elles sont envoyées séparément pour éviter toute injection.
	for column, value := range Args {
		whereClauses = append(whereClauses, fmt.Sprintf("%s = ?", column))
		params = append(params, value)
	}

  

	// Les conditions de notre query (requête) est construite ici de manière à être compris par SQL, whereClauses est transformé et ajouter dans whereString pour envoyer la requête
	// Si `whereClauses` contient `["age = ?", "name = ?"]`, alors `whereString` deviendra `"WHERE age = ? AND name = ?"`.
	whereString := ""
	if len(whereClauses) > 0 {
		whereString = "WHERE " + strings.Join(whereClauses, " AND ")
	}
	// Notre query est construite
	query := fmt.Sprintf("SELECT * FROM %s %s", tabelName, whereString)

  
	// La requête est construite ici (compilé)
	stmt, err := db.Prepare(query)
	if err != nil {
		return nil, nil, err
	}
	defer stmt.Close()

	// La requête est exécuté avec params, c'est ici qu'on veut éviter les injections
	rows, err := stmt.Query(params...)

	if err != nil {
		return nil, nil, err
	}

  
	// On récupère le resultat et l'envoie
	column, err := rows.Columns()

	if err != nil {
		return nil, nil, err
	}
	return column, rows, nil
}
```
##### Fin Ancre Select


Toutes ces manipulations de notre base de données permet de vérifier si le mail est utilisé par un autre compte ou non.
```go
// Si la len de notre réponse est différent de 0 c'est que le mail est déja utilisé
if len(authData) != 0 {
	nw.Error("Email is already used")
	log.Printf("[%s] [Register] %s", r.RemoteAddr, "Email is already used")
	return
}
```

Si tout ce passe bien la création du compte est possible. Il nous faut uniquement envoyé ces informations pour être stocker dans notre base de donnée. Une fonction go lié à la base de donnée est appelé.

```go 

// Les différentes informations sont envoyé dans les tables qui leurs correspondes, tout cela à l'aide d'une fonction go 


if err := utils.InsertIntoDb("Auth", db, register.Auth.Id, register.Auth.Email, register.Auth.Password); err != nil {

	nw.Error("Internal Error: There is a probleme during the push in the DB: " +     err.Error())
	log.Printf("[%s] [Register] %s", r.RemoteAddr, err.Error())
	return
} 

if err := utils.InsertIntoDb("UserInfo", db, register.Auth.Id, register.Auth.Email, register.FirstName, register.LastName, register.BirthDate, register.ProfilePicture, register.Username, register.AboutMe); err != nil {

	nw.Error("Internal Error: There is a probleme during the push in the DB: " +     err.Error())
	log.Printf("[%s] [Register] %s", r.RemoteAddr, err.Error())
	return
}
```

La fonction go importée est InsertIntoDb, elle nous permet de remplir la base de donnée.

```go 
func InsertIntoDb(tabelName string, db *sql.DB, Args ...any) error {
	// Créer une chaîne pour les placeholders
	placeholders := make([]string, len(Args))
	for i := range Args {
		placeholders[i] = "?"
	}
	
	// Préparer la requête SQL
	stmt, err := db.Prepare(fmt.Sprintf("INSERT INTO %s VALUES(%s)", tabelName, strings.Join(placeholders, ", ")))
	if err != nil {
		return err
	}
	
	// Exécuter la requête avec les arguments
	_, err = stmt.Exec(Args...)
	if err != nil {
		return err
	}
	
	return nil
}
```

L'utilisateur est enfin crée dans la base de donnée, un JWT est envoyé du back vers le front et la session est crée. Pour plus d'information sur les [JWT](./login.md#ancre-jwt).

```go
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(map[string]any{
		"Success":   true,
		"Message":   "Login successfully",
		"sessionId": GenerateJWT(register.Auth.Id),
	})
	if err != nil {
		log.Printf("[%s] [Register] %s", r.RemoteAddr,err.Error())
	}
```

