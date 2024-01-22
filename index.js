import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt, { hash } from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import env from "dotenv";
import GoogleStrategy from "passport-google-oauth2";


const app = express();
const port = 3000;
const saltRounds = 10;
env.config();



// const to store user details 
let user_id = [];


// connnection to the db
const db = new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DB,
    password: process.env.PG_PASSWORD,
    port:5432,
  });
db.connect();


// basic middleware
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));


// express session 
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    // how much time the cookie will be saved 
    // cookie: {
    //     maxAge: 1000 * 60 * 60 * 24,
    // }
}));
 


// initilalizng passport 
app.use(passport.initialize());
app.use(passport.session());


// async function to get data from DB
async function getText() {
    const userId = user_id.id;
    const result = await db.query("SELECT text_data FROM data WHERE user_id = $1 ORDER BY data_id ASC", [userId]);
    return result.rows; // Return the array directly
}


// routes secret home
app.get("/secrets", async (req, res) => {
    user_id = req.user
    const texts  = await getText();
    console.log(texts);
    console.log(user_id);
   if ( req.isAuthenticated()){
    res.render("secrets.ejs", { user: user_id, listtexts: texts });
   }else{
    res.redirect("/")
   }
})


// home route 
app.get("/", (req, res) => {
    res.render("home.ejs");
});

app.get("/auth/google",
passport.authenticate("google",{
    scope: ["profile", "email"],
}));



// submit route 
app.get("/submit", async (req, res) => {
    res.render("submit.ejs"); 
});

// submit post route 
app.post("/submit",  async (req, res) => {
    const userId = user_id.id
    const secret = req.body.secret
    try {
        await db.query("INSERT INTO data (text_data, user_id) VALUES ($1, $2)", [secret, userId]);
        const texts  = await getText();
        res.render("secrets.ejs",{ user: user_id,  listtexts: texts});
    } catch (err) {
        console.error(err);
    }
});

// login route
app.get("/login", (req, res) => {
    res.render("login.ejs");
});


app.get("/auth/google/secrets",passport.authenticate("google",{
    successRedirect: "/secrets",
    failureRedirect: "/login"
}));


// login post route 
app.post("/login", passport.authenticate("local",{
    successRedirect: "/secrets",
    failureRedirect: "/login"
}));



// route register 
app.get("/register", (req, res) => {
    res.render("register.ejs");
});



// post route register 
app.post("/register", async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    try {
        // password hashing 
        bcrypt.hash(password,saltRounds, async (err,hash) =>{
        if (err){
            console.log("error hashing",err);
        }
        else{
            const result  =  await db.query("INSERT INTO \"user\" (username, password) VALUES  ($1 , $2) RETURNING *", [username,hash]);
        const user  = result.rows[0];
        req.login(user, (err)=> {
            console.log("err")
            res.redirect("/secrets")
        })
        }
        })
        
    } catch (err) {
        console.error(err);
    }
});

  

// route logout
app.get("/logout", (req, res) => {
    req.logout((err) => {
        if (err) console.error(err);
        res.redirect("/")
    });
});




// passport session to verify login
passport.use(new Strategy(async function verify(username,password,cb) {
    try {
        const result = await db.query("SELECT * FROM \"user\" WHERE username = $1", [username]);

        if (result.rows.length > 0) {
            const user = result.rows[0];
            const storedHashedPassword = user.password
            // verifying with hashing
            bcrypt.compare(password , storedHashedPassword, (err , result) =>{
                if (err) {
                    return cb(err);
                  } else {
                    if (result) {
                        return cb(null, user)
                        // res.render("secrets.ejs", { user: user, listtexts: texts });
                      } else {
                        return cb(null, false);
                      }
                  }
            });
            } else {
            return cb(null, false);
        }
    } catch (err) {
        return cb(err);
    }
}));




// google authentication 
passport.use(
    "google",
    new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/google/secrets",
        userProfile: "https://www.googleapis.com/oauth2/v3/userinfo",
    }, async (accessToken, refreshToken , profile, cb) => {
        console.log(profile);
        try {
            const result = await db.query("SELECT * FROM \"user\" WHERE username = $1",[profile.email]);
            if (result.rows.length === 0){
                const newUser = await db.query("INSERT INTO \"user\" (username, password) VALUES  ($1 , $2)", [profile.email, "google"]);
                cb(null, newUser.rows[0]);
            }else {
                cb(null,result.rows[0]);
            }
        } catch(err) {
            cb(err);
        }
    })
)


passport.serializeUser((user , cb)=>{
    cb(null, user);
})

passport.deserializeUser((user , cb)=>{
    cb(null, user);
})

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
