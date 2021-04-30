const express = require('express');
const path = require('path');
const bodyParser =  require('body-parser')
const mongoose = require('mongoose')
const User = require('./model/user')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const JWT_SECRET = "bangyourheadonthekeyboard" //if your secret is leaked, your json payload can be manipulated 

mongoose.connect('mongodb://localhost:27017/login-app-db',{
    useNewUrlParser: true,
    useUnifiedTopology:true,
    useCreateIndex:true
})
const app = express();
app.use('/',express.static(path.join(__dirname,'static')));//if a user requests , localhost:9999/image.jpg, it goona hit this middleware , so ganna serve you this static file from static folder
app.use(bodyParser.json())//middleware to decode the body coming in 

app.post('/api/change-password', async (req, res) => {
	const { token,newpassword:plainTextPassword } = req.body//we get a json web token in body 

  

    try{
    const user = jwt.verify(token,JWT_SECRET)//make sure that token is not tampered with, and returns only the payload part 
    console.log("JWT Decoded:",user)

    if (!plainTextPassword || typeof plainTextPassword !== 'string') {
		return res.json({ status: 'error', error: 'Invalid password' })
	}
    if (plainTextPassword.length < 5) {
		return res.json({
			status: 'error',
			error: 'Password too small. Should be atleast 6 characters'
		})
	}

        //valid token/user
        const _id = user.id
        const hashedPassword= await bcrypt.hash(plainTextPassword,10)
        await User.updateOne({_id},{$set:{password:hashedPassword}})//select that user and change the password

        res.json({status:'ok'})

    }catch(error){
        res.json({status:'error',error:'login first'})

    }
    
    
})

app.post('/api/login',async(req,res)=>{
    const{username,password}=req.body
    const user = await User.findOne({username}).lean()//find the user 

    if (!user) {
		return res.json({ status: 'error', error: 'Invalid username/password' })
	}

    if(await bcrypt.compare(password,user.password)){ //comapring the plain entered password with the hased password stored in db
        //the username , password combination is successfull

        const token  = jwt.sign({ //dont keep sensitive data in payload
            id:user._id ,
            username:user.username
        },JWT_SECRET)

        return res.json({status :'ok', data:token })

    }

    res.json({status:'error',error: 'Invalid username/password'})
})
//Client->Server : Your client *somehow* has to authenticate who it is 
//Why - Server is a central computer which you cannot control
//Client(john) -> a computer which you dont control

// ways to authenticate that is he really who he says he is
//1.Client proves itself somehow on the secret/data (secret/data is NON CHANGABLE) (JWT)
//2.Client-Server share a secret (Cookie)

//JWT is not an encryption , not for storing sensitive data , it just saying that hey client you can go ahead and use this token to communicate with me and i would know you are the client you say you are
//jwt token has 3 parts, only middle part has payload other 2 are for validation , that this data has not been tampered with


app.post('/api/register',async (req,res)=>{ //async as we will male db calls 

    console.log(req.body);//we need body parser to access body data 

    const {username,password:plainTextPassword} = req.body //renaming when destructuring

//validation
    if (!username || typeof username !== 'string') {
		return res.json({ status: 'error', error: 'Invalid username' })
	}
    if (!plainTextPassword || typeof plainTextPassword !== 'string') {
		return res.json({ status: 'error', error: 'Invalid password' })
	}
    if (plainTextPassword.length < 5) {
		return res.json({
			status: 'error',
			error: 'Password too small. Should be atleast 6 characters'
		})
	}
//
    const password = await bcrypt.hash(plainTextPassword,10);

    //now thow the username,password combo in db
    try{
        const response = await User.create({
            username,
            password
        })
        
        console.log('User created successfully',response);

    }catch(error){
        if(error.code===11000){
            //dup key
            return res.json({status:'error',error:'Username already in use'})
        }
        throw error
    }
    

    res.json({status:'ok'})//automatically set headers 
})
app.listen(9999,()=>{
    console.log("server up and running");
})



//we use hashing of passwords , egs using-> bcrypt,md5,sha1,sha256,sha512
//in hashing algorithms 
//1.The collision should be improbable
//2.the algorithm should be slow (as if attacked by a brute force high cpu consuption)