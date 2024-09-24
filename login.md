## Objectif

Nous devons permettre à l'utilisateur de se connecter à son compte. Il est nécessaire de faire en sorte de vérifier que les informations saisi sont envoyé du front vers le back et de les comparer si l'utilisateur est dans la base de donnée et que les informations saisie sont correcte.  Une session sera ensuite crée pour que l''utilisateur puisse accéder par la suite au site sans mot de passe. 


## Réalisation

Nous devons lire l'objet JSON envoyé par le front est de vérifier que tout est dans l'ordre.
Il est essentiel de décode du JSON et le mettre dans une structure en go. Ce qui permettra de vérifier le format ; si il y'a des zones vides, si le mail existe ou qu'il est correcte et surtout de comparer le mot de passe mis avec notre mot de passe crypté.
Su tout est en ordre une requête est envoyé au front avec la confirmation de l'identité de l'utilisateur et également un JWT.


## Conception 

Nous devons recrée une structure pour ajouter une méthode et lire le body de la requête.
```go
nw := model.ResponseWriter{
	ResponseWriter: w,
}

body, _ := io.ReadAll(r.Body)
defer r.Body.Close()
```

Décoder le JSON en une structure GO pour pouvoir le manipuler. Le format est celui de notre structure pour l'authentification : AUTH.
```go
var loginData model.Auth
json.Unmarshal(body, &loginData)
```

Il nous faut vérifier si les champs contenant mail et le mot de passe ne sont pas vide. 
```go
if loginData.Email == "" || loginData.Password == "" {
	nw.Error("There is an empty field")
	log.Printf("[%s] [Login] %s", r.RemoteAddr, "There is an empty field")
	return
}
```

Nous pouvons regardé dans la base de donnée si le mail saisi existe. Tout cela avec des fonctions important utilisé pour manipulé notre base de donnée. Pour en savoir plus [Manipulation SQL](./register.md#ancre-select).
Toutes les informations pour l'authentification sont également récuperer.
```go
// La fonction SelectFromDB est appelé et permet de vérifier si le mail est présent 
authData, err := utils.SelectFromDb("Auth", db, map[string]any{"Email": loginData.Email})
if err != nil {
	nw.Error("Internal error: Problem during database query: " + err.Error())
	log.Printf("[%s] [Login] %s", r.RemoteAddr, err.Error())
	return
}

// Vérifie que le mail existe bien
if len(authData) != 1 {
	nw.Error("Incorrect email")
	log.Printf("[%s] [Login] %s", r.RemoteAddr, "Incorrect email")
	return
}
```
Le resultat est parse (converti) avec la fonction parseUserData.
```go
	userData, err := parseUserData(authData[0])
	if err != nil {
		nw.Error(err.Error())
		log.Printf("[%s] [Login] %s", r.RemoteAddr, err.Error())
		return
	}
```

La fonction nous permet de passer assez facilement d'une map à une structure en go en passant par du JSON. 

```go
func parseUserData(userData map[string]any) (model.Auth, error) {

    // On ne transforme pas la map directment à notre structure en go, itiliser json.Marshal et json.Unmarshal est une approche standard qui facilite le processus.

    // Notre structure go Auth comporte l'ID, L'Email, le Password et le ConfirmPassword.


    // Conversion d'une map de string en JSON
	serializedData, err := json.Marshal(userData)
	if err != nil {
		return model.Auth{}, errors.New("internal error: conversion problem")
	}


    // Conversion du JSON en notre structure en go
	var authResult model.Auth
	err = json.Unmarshal(serializedData, &authResult)

	return authResult, err
}
```


Avec la manipulation de la base de donnée et les informations précedentes on peut enfin déterminer un user. Donc il est enfin possible de vérifier que le mot de passe récuperer et converti en structure go correspond avec le hache.
```go
    // Actuellement dans userData.Password il y'a le hache et le sel, qui nous permette de comparer le mot de passe saisi qui se trouve dasn loginData.Password
    // Ce processus permet de n'avoir jamais le mot de passe en clair dans la base de donnée et uniquement le hache et le sel

    // Bcrypt transforme le mot de passe avec un algorithme et nous donne un hache (mot de passe crypté) et un sel. Le sel assure l'alétoire dans l'algorithme et empeche que deux mot de passe identiques ont le meme hache
    // Pour vérifier que c'est le bon mot de passe on le crypte avec le meme algotithme et le meme sel, si le hache est identique c'est que c'est le bon mot de passe

	if err = bcrypt.CompareHashAndPassword([]byte(userData.Password), []byte(loginData.Password)); err != nil {
		nw.Error("Invalid password")
		log.Printf("[%s] [Login] %s", r.RemoteAddr, err.Error())
		return
	}
```



##### Ancre JWT

L'authentification est fait, si toutes les informations saisi sont correcte il nous faut maintenir la session dans le navigateur. Pour cela on crée et envoie un JWT (JSON Web Token). Pour mieux comprendre la structure des JWT [JWT-Schéma](./images/JWT.png)

```go
// Le JWT est semblable à un cookie de session mais il contient des donnée
func GenerateJWT(str string) string {


    // Le JWT possède des informations sur les utilisateurs et permet de garder une session ouverte elle possède des informations utilisateurs et une clé secrète unique à l'application.
    // La clé secrète est la partie la plus importante et est crypté avec un facteur de difficulté de 12 qui est rapide et sécuriser. Le cout maximum est de 31 mais cela prends trop de temps. Le cout actuel est le plus adapté pour notre cas.

	header := base64.StdEncoding.EncodeToString([]byte(`{
		"type": "JWT"
	}`))

	content := base64.StdEncoding.EncodeToString([]byte(str))

retry:
	key, err := bcrypt.GenerateFromPassword([]byte(model.SecretKey), 12)
	if err != nil {
		fmt.Println(err)
	}
	if strings.Contains(string(key), ".") {
		goto retry
	}

	result := header + "." + content + "." + string(key)

	return result
}
```
##### Fin de l'ancre JWT
