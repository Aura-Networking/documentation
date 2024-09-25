# Verification


## Objectif

Nous devons permettre à l'utilisateur de se connecter à son compte sans saisir ces informations si il s'est déja connecter auparavant. La session doit etre conserver dans le navigateur.

## Réalisation

Nous devons lire l'objet JSON envoyé par le front et vérifié qu'il y'a une une session.
Il est essentiel de décomposé le format de notre session qui est un JWT. Le scinder en 3 partie et déterminé si c'est bien une session fournie par notre système à l'aide de la clé secrete qui est crypté à chaque fois.
Si c'est bien fournie par notre système nous pouvons déterminer l'ID et faire correspondre à un ID d'un de nos utilisateurs dans notre base de donnée.
Enfin nous devons envoyé la confirmation d'identité du front vers le back.


## Conception


Nous devons recréer une structure pour ajouter une méthode et lire le body de la requête.
```go
nw := model.ResponseWriter{
	ResponseWriter: w,
}

body, _ := io.ReadAll(r.Body)
defer r.Body.Close()
```


Décoder le JSON pour pouvoir le manipuler en string.

```go
var sessionId string
json.Unmarshal(body, &sessionId)
```


Le contenue de la requete est séparer en trois partie, en les délimittant par des points. Voir schéma [JWT](./images/JWT.png)
```go
splitSessionId := strings.Split(sessionId, ".")
if len(splitSessionId) != 3 {
	nw.Error("Invalid JWT")
	log.Printf("[%s] [VerificationSessionId] %s", r.RemoteAddr, "Invalid JWT")
	return
}
```


La troisième partie qui contient une version hacher (à l'aide de bcrypt) de notre clé secrète. Chaque requete à un hache différent à l'aide du sel. Le sel permet de comparé l'état initiale et la version hacher de notre clé.
Pour plus d'information sur l'utilisation de [Bcrypt](./register.md#ancre-bcrypt)

```go
if err := bcrypt.CompareHashAndPassword([]byte(splitSessionId[2]), []byte(model.SecretKey)); err != nil {
	nw.Error("Invalid JWT")
	log.Printf("[%s] [VerificationSessionId] %s", r.RemoteAddr, "Invalid JWT")
	return
}
```

Une fois s'etre assuré que la session est bien fournie par nous. La deuxieme partie du JWT est traité. Elles est en base64, il nous faut la décoder et déterminer quel utilisateur possede cette ID.
La fonction go de manipultaton du SQL est utilisé, voir [Select](./register.md#ancre-select)

```go
decryptId, err := base64.StdEncoding.DecodeString(splitSessionId[1])
if err != nil {
	nw.Error("Internal Error: There is a probleme during the decrypt of the sessionId : " + err.Error())
	log.Printf("[%s] [VerificationSessionId] %s", r.RemoteAddr, err.Error())
	return
}


authData, err := utils.SelectFromDb("Auth", db, map[string]any{
	"Id": string(decryptId),
})
if err != nil {
	nw.Error("Internal error: Problem during database query: " + err.Error())
	log.Printf("[%s] [VerificationSessionId] %s", r.RemoteAddr, err.Error())
	return
}


if err := CheckDatasForCookie(authData); err != nil {
	nw.Error(err.Error())
	log.Printf("[%s] [VerificationSessionId] %s", r.RemoteAddr, err.Error())
	return
}
```

La fonction CheckDatasForCookie est appelé. Elle permet simplement de vérifier si l'ID est posséder par un utilisateur et qu'il y'a aucun probleme sur les informations d'utilisateurs.


```go
func CheckDatasForCookie(authData []map[string]any) error {
	if len(authData) != 1 {
		return errors.New("nobody have this Id")
	}

	userData, err := parseUserData(authData[0])
	if err != nil {
		return err
	}

	if userData.Id == "" || userData.Email == "" || userData.Password == "" {
		return errors.New("nobody have this Id")
	}

	return nil
}
```


Enfin, si tout est en ordre un message de confirmation est envoyé du back vers le front. La session est enfin établie en sécurité.

```go
w.Header().Set("Content-Type", "application/json")
err = json.NewEncoder(w).Encode(map[string]any{
	"Success": true,
	"Message": "Valid cookie",
})

if err != nil {
	log.Printf("[%s] [VerificationSessionId] %s", r.RemoteAddr, err.Error())	}
```

