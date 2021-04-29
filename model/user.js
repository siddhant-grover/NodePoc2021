//model to enforce a schema on db , managing dataflow

const mongoose  = require("mongoose")

const UserSchema =  new mongoose.Schema({
  username:{type:String,required:true, unique: true},//username has to be unique , unique is implemented using idexes in mongodb
  password:{type:String,required:true}
},{
    collection:'users'
})

const model = mongoose.model('UserSchema',UserSchema)//register this as a model in mongoose

module.exports = model
 