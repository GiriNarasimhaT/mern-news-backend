const mongoose = require('mongoose');
const {Schema,model}=mongoose;

const UserSchema = new Schema({
    profilePicture:String,
    username:{type: String, required:true, unique:true},
    email:{type: String, required:true, unique:true},
    password:{type:String, required:true},
    articlecount: { type: Number, default: 0 },
    bio:String,
});

const UserModel = model('User',UserSchema);

module.exports = UserModel;