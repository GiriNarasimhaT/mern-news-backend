const express = require('express');
const cors = require('cors');
const { mongoose } = require('mongoose');
const User = require('./models/User');
const Article = require('./models/Article');
const app = express();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const uploadMiddleware = multer({ dest: 'uploads/'});
const fs = require('fs');
require('dotenv').config();
const path = require('path');

const salt = bcrypt.genSaltSync(10);
const secret = 'dh27rgfyu46f7twyufg46tf8y34rfg783';

const PORT = process.env.PORT || 4000;

const DB = process.env.DATABASE;

mongoose.connect(DB).then(() => {
  console.log('Connected to Database');
}).catch((error) => {
  console.error('Error connecting to MongoDB', error);
});

const domainsFromEnv = process.env.CORS_DOMAINS || ""

const whitelist = domainsFromEnv.split(",").map(item => item.trim())

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || whitelist.indexOf(origin) !== -1) {
      callback(null, true)
    } else {
      callback(new Error("Not allowed by CORS"))
    }
  },
  credentials: true,
}
app.use(cors(corsOptions))

app.use(express.json());
app.use(cookieParser());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.post('/register', async (req,res)=>{
    const {username,email,password}=req.body;
    try{
        const existingUser = await User.findOne({ email: { $regex: new RegExp('^' + email + '$', 'i') } }); //case insensitive
        if (existingUser) {
            return res.status(400).json({"error": "Account with that email already exists"});
        }

        const existingusername = await User.findOne({ username });
        if (existingusername) {
            return res.status(400).json({"error": "Username is taken, please try another" });
        }

        const userDoc = await User.create({
            profilePicture:'',
            username,
            email,
            password:bcrypt.hashSync(password,salt),
            articlecount:0,
            bio:'',
        });
        res.status(200).json('Registered Successfully');
    } catch(e){
        res.status(400).json(e);
    }
});

app.post('/login', async (req, res) => {
    const {email,password}=req.body;
    const userDoc = await User.findOne({ email: { $regex: new RegExp('^' + email + '$', 'i') } }); //case insensitive
    if(userDoc){
        const passOk = bcrypt.compareSync(password,userDoc.password);
        if (passOk){
            jwt.sign({email,id:userDoc._id,username:userDoc.username,profilePicture:userDoc.profilePicture},secret,{},(err,token)=>{
                if (err){
                    console.log(err);
                    throw err;
                }
                res.cookie('token',token,{
                    expires: new Date(Date.now() + 60 * 60 * 1000), // 1 hour
                    httpOnly: false,
                    secure: true,
                    sameSite:'none'
                }).json({
                    id:userDoc._id,
                    username:userDoc.username,
                    profilePicture:userDoc.profilePicture,
                    email,
                });
            });
        } else{
            res.status(400).json('Wrong Password')
        }
    }
    else{
        res.status(400).json('No Account found with that email')
    }
});

app.get('/profile', (req,res)=>{
    if (req.cookies.token){
        const {token} = req.cookies;
        if(token){
            jwt.verify(token,secret,{},(err,info)=>{
                if (err) throw err;
                res.json(info);
            });
        }
        else{
            res.json('');
        }
    }
});

app.post('/logout', (req, res) => {
    res.cookie('token', '', {
      expires: new Date(Date.now() - 1),
      httpOnly: false,
      secure: true,
      sameSite: 'none'
    }).json('ok');
  });

// Article Creation
app.post('/article', uploadMiddleware.single('file'), async (req, res) => {
    const token = req.cookies.token;
    if (!token) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    jwt.verify(token, secret, {}, async (err, info) => {
      if (err) throw err;
      const { title, summary, content } = req.body;
      let newPath = '';
      if (req.file) {
        const { originalname, path: filePath } = req.file;
        const parts = originalname.split('.');
        const ext = parts[parts.length - 1];
        newPath = filePath + '.' + ext;
        fs.renameSync(filePath, newPath);
      }
      const articleDoc = await Article.create({
        title,
        summary,
        content,
        cover: newPath,
        author: info.id,
      });
      // incrementing articlecount
      await User.findOneAndUpdate(
        { _id: info.id },
        { $inc: { articlecount: 1 } },
        { new: true }
      );
      res.json(articleDoc);
    });
  });  

// Article Updation
app.put('/article', uploadMiddleware.single('file'), async (req, res) => {
    let newPath = null;
    if (req.file) {
        const { originalname, path: filePath } = req.file;
        const parts = originalname.split('.');
        const ext = parts[parts.length - 1];
        newPath = filePath + '.' + ext;
        fs.renameSync(filePath, newPath);
    }
    
    const token = req.cookies.token;
    if (!token) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    jwt.verify(token,secret,{},async (err,info)=>{
        if (err) throw err;
        const {id,title,summary,content}=req.body;
        const articleDoc = await Article.findById(id);
        if (!articleDoc) {
            return res.status(404).json("Page not found");
        }
        const user = JSON.stringify(articleDoc.author)===JSON.stringify(info.id);
        if (!user){
            return res.status(400).json('Article updation failed');
        }
        
        await articleDoc.updateOne({
            title,
            summary,
            content,
            cover: newPath ? newPath : articleDoc.cover,
        });

        // Delete old articlecover
        if (newPath && articleDoc.cover) {
            const oldFilePath = path.join(__dirname, articleDoc.cover);
            fs.unlink(oldFilePath, (err) => {
            if (err) throw err;
            });
        }
        res.json(articleDoc);
    });
});

//Profile Updation
app.put('/profile', uploadMiddleware.single('file'), async (req, res) => {
    let newPath = null;
    if (req.file) {
        const { originalname, path: filePath } = req.file;
        const parts = originalname.split('.');
        const ext = parts[parts.length - 1];
        newPath = filePath + '.' + ext;
        fs.renameSync(filePath, newPath);
    }
    
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).json({ message: 'Unauthorized' });
    }
    try {
        const info = jwt.verify(token, secret);
        const {id,email,username,articlecount,bio}=req.body;
        const userDoc = await User.findById(id);
        if (!userDoc) {
            return res.status(404).json("User not found");
        }
        const user = JSON.stringify(userDoc._id)===JSON.stringify(info.id);
        if (!user){
            return res.status(400).json('You are not Logged in');
        }

        // Delete old profile picture file
        if (newPath && userDoc.profilePicture) {
            const oldFilePath = path.join(__dirname, userDoc.profilePicture);
            try {
                await fs.promises.unlink(oldFilePath);
            } catch (err) {
                console.error(err);
            }
        }

        const updatedUserData = {
            email,
            username:username,
            profilePicture: newPath ? newPath : userDoc.profilePicture,
            articlecount,
            bio,
        };

        await userDoc.updateOne(updatedUserData);
        
        const updatedToken = jwt.sign({
            email,
            id,
            username: username,
            profilePicture: newPath ? newPath : updatedUserData.profilePicture,
        }, secret, {});

        res.cookie('token', updatedToken,{
            expires: new Date(Date.now() + 60 * 60 * 1000), // 1 hour
            httpOnly: false,
            secure: true,
            sameSite:'none'
        }).json({
            id,
            email,
            username:username,
            profilePicture:newPath ? newPath : userDoc.profilePicture,
        });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: 'Internal server error' });
    }
});

//Delete Article
app.delete('/delete', uploadMiddleware.single('file'), async (req, res) => {
    const token = req.cookies.token;
    if (!token) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    jwt.verify(token,secret,{},async (err,info)=>{
        if (err) throw err;
        const {id}=req.body;
        const articleDoc = await Article.findById(id);
        const isAuthor = JSON.stringify(articleDoc.author)===JSON.stringify(info.id);
        if (!isAuthor){
            return res.status(400).json('You are not the author');
        }
        
        await articleDoc.deleteOne();

        // decrementing articlecount
        await User.findOneAndUpdate(
            { _id: info.id },
            { $inc: { articlecount: -1 } },
            { new: true }
        );

        // Delete articlecover
        if (articleDoc.cover) {
            const filePath = path.join(__dirname, articleDoc.cover);
            fs.unlink(filePath, (err) => {
            if (err) throw err;
            });
        }
        res.json(articleDoc);
    });
});

// Delete User
app.delete('/deleteuser', uploadMiddleware.single('file'), async (req, res) => {
    const token = req.cookies.token;
    if (!token) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    jwt.verify(token,secret,{},async (err,info)=>{
        if (err) throw err;
        const {id}=req.body;
        const userDoc = await User.findById(id);
        const user = JSON.stringify(userDoc._id)===JSON.stringify(info.id);
        if (!user){
            return res.status(400).json('You have not Singed In');
        }
        await userDoc.deleteOne().then(
            res.cookie('token','',{
                expires: new Date(Date.now() - 1),
                httpOnly: false,
                secure: true,
                sameSite:'none'
            }).json('ok')
        );

        // Delete profile picture
        if (userDoc.profilePicture) {
            const filePath = path.join(__dirname, userDoc.profilePicture);
            fs.unlink(filePath, (err) => {
            if (err) throw err;
            });
        }
    });
});

// Delete all articles
app.delete('/deletearticles', uploadMiddleware.single('file'), async (req, res) => {
    const token = req.cookies.token;
    if (!token) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
    jwt.verify(token,secret,{},async (err,info)=>{
        if (err) throw err;
        const {id}=req.body;
        const user = JSON.stringify(id)===JSON.stringify(info.id);
        const userDoc=User.findById(info.id);
        if (!user){
            return res.status(400).json('You have not Singed In');
        }

        await Article.deleteMany({author:id});
        // set articlecount to 0
        await User.findOneAndUpdate(
            { _id: info.id },
            { articlecount: 0 },
            { new: true }
        );

        //Delete all articlecovers
        const articles = await Article.find({ author: id });
        for (const article of articles) {
            if (article.cover) {
                const filePath = path.join(__dirname, article.cover);
                fs.unlink(filePath, (err) => {
                if (err) throw err;
                });
            }
        }
        res.json('ok');
    });
});

app.get('/articles', async (req,res)=>{
    res.json(await Article.find().populate('author',['_id','username']).sort({createdAt:-1}).limit(20));
});

app.get('/article/:id',async (req,res)=>{
    try {
        const { id } = req.params;
        const articleDoc = await Article.findById(id).populate('author',['username']);
        if (!articleDoc) {
            return res.status(404).json("{ error: 'Article not found' }");
        }
        res.json(articleDoc);
    } catch (error) {
        res.status(400).json("{ error: 'Invalid id' }");
    }
});

app.get('/user/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const userDoc = await User.findById(id).select('-password');
        if (!userDoc) {
            return res.status(404).json({ error: 'User not found' });
        }
        const articles = await Article.find({ author: id })
            .populate('author', ['_id', 'username'])
            .sort({ createdAt: -1 })
            .limit(20);
        
        res.json({ user: userDoc, articles });
    } catch (error) {
      res.status(400).json({ error: 'Invalid id' });
    }
  });

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json('Internal Server Error');
});

app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});