//requires de dépendances

const fastify = require("fastify")({ logger: true });
const path = require("path");
const fastifySession = require("fastify-session");
const fastifyCookie = require("fastify-cookie");
const bcrypt = require("bcrypt");
const mysql = require("mysql");


const saltRounds = 10;

// établissement de la connection

function dbInit() {
   const connection = mysql.createConnection({
      host: "localhost",
      user: "root",
      password: "unMdpAMettreDansLeFicherEnv",
      database: "users",
      port: 8080,
   });

   connection.connect();
   return connection;
}

// set le folder public en static

fastify.register(require("fastify-static"), {
   root: path.join(__dirname, "public"),
   prefix: "/public/",
});

// register ejs (communication back et front) avec le module point-of-view

fastify.register(require("point-of-view"), {
   // on déclare que nous utilisons ejs
   engine: {
      ejs: require("ejs"),
   },
});

// déclaration de l'api fastify-formbody permettant d'acceder aux body lors de requetes post

fastify.register(require("fastify-formbody"));

// on déclare l'utilisation de fastifyCookie qui nous permettera d'utiliser fastifySession

fastify.register(fastifyCookie);
fastify.register(fastifySession, {
   cookieName: "sessionId",
   secret: "a secret with minimum length of 32 characters",
   // http donc secure = false
   cookie: { secure: false },
   expires: 1800000,
});

//méthode get route get

fastify.get("/", (response, reply) => {
   // dès que l'on arrive sur la page principale:
   // on montre la page ejs avec divers informations comme celles de la session

   reply.view("public/html/index.ejs", {
      name: response.session.infos?.name ?? "",
      email: response.session.infos?.mail ?? "",
   });
});

// quand on arrive sur /connect, on montre la page connection
fastify.get("/inscription", (response, reply) => {
   reply.view("public/html/connect.ejs", { error: response.session.error });
});

// route post pour connect, dès qu'on execute une requete post on stock les valeurs dans la session

fastify.post("/inscription", function (response, reply) {
   // on récupère les valeurs du body
   const { name, mdp, email } = response.body;

   try {
      //init de la databe
      const db = dbInit();

      db.query(
         "SELECT * FROM users.utilisateur WHERE (pseudo=?);",
         name,
         (err, res, fields) => {
            if (err) throw err;

            console.log(res);

            if (res.length === 0) {
               bcrypt.hash(mdp, saltRounds, function (err, hash) {
                  if (err) throw err;

                  // l'objet qui sera inséré dans la base de données

                  const inputs = { pseudo: name, mdp: hash, email: email };

                  // la requete

                  db.query(
                     "INSERT INTO users.utilisateur SET ?",
                     inputs,
                     (err, res) => {
                        if (err) throw err;
                        reply.redirect("/");
                     }
                  );
               });
            } else {
               console.log("oh no");
               response.session.error = "ce compte existe déjà !";
               reply.redirect("/inscription");
            }
         }
      );
      //chiffrement du mot de passe
   } catch (err) {
      console.log(err);
   }

   // on stock ces valeurs dans la session
});

fastify.get("/disconnect", (request, reply) => {
   reply.view("public/html/disconnect.ejs");
   request.session.infos = {};
   reply.redirect("/");
});

fastify.get("/connexion", (request, reply) => {
   reply.view("public/html/login.ejs", { error: request.session.error });
});

fastify.post("/connexion", (request, reply) => {
   const { name, mdp } = request.body;
   const put = { pseudo: name, mdp: mdp };
   try {
      const db = dbInit();
      db.query(
         "SELECT * FROM users.utilisateur WHERE (pseudo=?)",
         name,
         (err, res, fields) => {
            if (err) {
               throw err;
            }

            if (!res.length) {
               console.log("votre indentifiant n'est pas bon");
               request.session.error = "mauvais identifiant !";
               reply.redirect("/connexion");
               return;
            } else {
               let resultArray = Object.values(
                  JSON.parse(JSON.stringify(res[0]))
               );

               let hash = resultArray[1];
               bcrypt.compare(mdp, hash).then((result) => {
                  console.log(hash, result);

                  if (!result) {
                     console.log("mauvais mot de passe");
                     request.session.error = "mauvais mot de passe !";
                     reply.redirect("/connexion");
                  } else {
                     request.session.infos = {
                        name: resultArray[0],
                        mail: resultArray[2],
                     };
                     reply.redirect("/");
                  }
               });
            }
         }
      );
      db.end();
   } catch (err) {
      console.log(err);
   }
});

// fonction pour start le serveur

const start = async function () {
   try {
      await fastify.listen(3000);
   } catch (err) {
      fastify.log.error(err);
      process.exit(1);
   }
};

//start le serveur

start();
