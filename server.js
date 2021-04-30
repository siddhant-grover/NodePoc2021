const express = require('express');
const path = require('path');
const bodyParser =  require('body-parser')
const mongoose = require('mongoose')
const User = require('./model/user')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const JWT_SECRET = "bangyourheadonthekeyboard" 

mongoose.connect('mongodb://localhost:27017/login-app-db',{
    useNewUrlParser: true,
    useUnifiedTopology:true,
    useCreateIndex:true
})
const app = express();
app.use('/',express.static(path.join(__dirname,'static')));
app.use(bodyParser.json())//middleware to decode the body coming in 

function passwordValidation(plainTextPassword){
    if (!plainTextPassword || typeof plainTextPassword !== 'string') {
		return { status: 'error', error: 'Invalid password' }
	}
    if (plainTextPassword.length < 5) {
		return {
			status: 'error',
			error: 'Password too small. Should be atleast 6 characters'
		}
	}
    else
    return;
}

app.post('/api/change-password', async (req, res) => {
	const { token,newpassword:plainTextPassword } = req.body//we get a json web token in body 

  

    try{
    const user = jwt.verify(token,JWT_SECRET)
        //console.log("JWT Decoded:",user)

        if(passwordValidation(plainTextPassword))
        return res.json(passwordValidation(plainTextPassword))

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

    if(await bcrypt.compare(password,user.password)){ 

        const token  = jwt.sign({ //dont keep sensitive data in payload
            id:user._id ,
            username:user.username
        },JWT_SECRET)

        return res.json({status :'ok', data:token })

    }

    res.json({status:'error',error: 'Invalid username/password'})
})


app.post('/api/register',async (req,res)=>{ 
        //console.log(req.body);

    const {username,password:plainTextPassword} = req.body //renaming when destructuring

//validation
    if (!username || typeof username !== 'string') {
		return res.json({ status: 'error', error: 'Invalid username' })
	}
     
    if(passwordValidation(plainTextPassword))
    return res.json(passwordValidation(plainTextPassword))
//
    const password = await bcrypt.hash(plainTextPassword,10);

    //now thow the username,password combo in db
    try{
        const response = await User.create({
            username,
            password
        })
        
       // console.log('User created successfully',response);

    }catch(error){
        if(error.code===11000){
            //dup key
            return res.json({status:'error',error:'Username already in use'})
        }
        throw error
    }
    

    res.json({status:'ok'})//automatically set headers 
})
app.listen(5000,()=>{
    console.log("server up and running");
})
