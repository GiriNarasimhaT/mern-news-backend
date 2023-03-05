const mongoose = require("mongoose");
const { Schema,model } = require("mongoose");

const ArticleSchema = new Schema({
    title:String,
    summary:String,
    content:String,
    cover:String,
    author:{type:Schema.Types.ObjectId, ref:'User'}
},{
    timestamps:true,
});

const ArticleModel=model('Article',ArticleSchema);

module.exports = ArticleModel;