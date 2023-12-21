import express from 'express'
import path from 'path'
import mongoose from 'mongoose'
import cookieParser from 'cookie-parser'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcrypt'

const app = express()
const port= 3000

//db connection
mongoose.connect("mongodb://localhost:27017", {
    dbName: "backend"
}). then(()=>{
    console.log("Database Connected");
}).catch((e)=>{
    console.log(e);
})

//create schema
const userSchema = new mongoose.Schema({
    name:{
        type:String,
        required: true
    },
    email:{
        type:String,
        required: true
    },
    password:{
        type:String,
        required: true
    }
})

//create model 
const User = mongoose.model("User", userSchema)

//setting up view engine
app.set("view engine", "ejs")

//using middleware
app.use(express.static(path.join(path.resolve(), "public")))   //for acessing static file 
app.use(express.urlencoded({extended:true}))   //for accessing req data
app.use(cookieParser()) //for accessing cookies


const isAuthenticated = async (req, res, next)=>{
        // console.log(req.cookies.token);
       
    const {token} = req.cookies;
    if(token){
        let decoded = jwt.verify(token, 'suresh1234')
        // console.log(decoded)
        req.user= await User.findById(decoded._id)  //store data from user_id in req.user 

        next();
    }else{
        res.render("login")
    }   
}

app.get('/', isAuthenticated, (req,res)=>{
    // console.log(req.user);

        res.render("logout", {name: req.user.name})
      
})

app.get('/login', (req, res)=>{
    res.render("login")
})

app.get('/register', (req,res)=>{
    res.render("register")
  
})

app.post('/login', async(req, res)=>{
    const {email, password}= req.body;
        let user = await User.findOne({email});
        // console.log(user)
        if(!user) return res.redirect('/register');

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            // Pass the message variable when rendering the template
            return res.render('login', {email, message: 'Incorrect Password' });
          }
        const token = jwt.sign({_id: user._id}, 'suresh1234')

        res.cookie("token", token , {
            expires: new Date(Date.now()+ 60*1000),
            httpOnly: true
        })
        res.redirect("/")
})



app.post('/register', async (req,res)=>{
    const {name, email, password} = req.body
    
    let user = await User.findOne({email})
    if(user){
        return res.redirect('/login')

    }
    const hashedPassword = await bcrypt.hash(password, 10)
        user = await User.create({
        name: name,
        email: email, 
        password: hashedPassword
    })

    const token = jwt.sign({_id: user._id}, 'suresh1234')

    res.cookie("token", token , {
        expires: new Date(Date.now()+ 60*1000),
        httpOnly: true
    })
    res.redirect("/")
})

app.get('/logout', (req,res)=>{
    res.cookie("token", null, {
        expires: new Date(Date.now()),
    })
    res.redirect("/")
})

app.listen(3000, ()=>{
    console.log(`server running at port ${port}`);
})