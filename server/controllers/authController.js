import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../models/userModel.js'
import { text } from 'express';
import transporter from '../config/nodemailer.js';

export const register = async (req,res)=>{

    const {name,email,password} = req.body;

    if(!name || !email || !password){
        return res.json({success:false,message:'Missing Details'});
    }

    try {

        const existingUser = await userModel.findOne({email});

        if(existingUser){
            return res.json({success:false,message:'User already exists'});

        }

        const hashedPassword = await bcrypt.hash(password,10);

        const user = new userModel({
            name,
            email,
            password:hashedPassword
        });

        await user.save();

        const token = jwt.sign({id:user._id},process.env.JWT_SECRET,{expiresIn:'7d'});

        res.cookie('token',token,{
            httpOnly:true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7*24*60*60*1000 
        })

        //sending email
        const mailOptions={
            from:process.env.SENDER_EMAIL,
            to:email,
            subject:'Welcome to AuthStack',
            text:`Welcome to Authstack Website. Your Account has been created with email id: ${email} `
        };

        await transporter.sendMail(mailOptions);


        return res.json({success:true});

    } catch (error) {
        res.json({success:false,message:error.message});
    }
}

export const login = async (req,res)=>{

    const {email,password} = req.body;

    if(!email || !password){
        return res.json({success:false,message:'Email or Password is missing'});
    }

    try {
        const user = await userModel.findOne({email});

        if(!user){
            return res.json({success:false,message:"Invalid Email"});
        }

        const isMatch = await bcrypt.compare(password,user.password);

        if(!isMatch){
             return res.json({success:false,message:"Invalid password"});
        }

        const token = jwt.sign({id:user._id},process.env.JWT_SECRET,{expiresIn:'7d'});

        res.cookie('token',token,{
            httpOnly:true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7*24*60*60*1000 
        })

        return res.json({success:true});
    } catch (error) {
        return res.json({success:false,message:error.message});
    }
}

export const logout = async (req,res)=>{
    try {
        res.clearCookie('token',{
            httpOnly:true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict'
        })

        return res.json({success:true,message:"User Logged out"})
    } catch (error) {
        return res.json({success:false,message:error.message});
    }
}

//send verification email to user's email
export const sendVerifyOtp = async (req,res) =>{
    try {
        const {userId} = req.userId;

        const user = await userModel.findOne({userId});

        if(user.isAccountVerified){
            return res.json({success:false,message:"Account Already Verified"});
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));

        user.verifyOtp = otp;
        user.verifyOtpExpiresAt= Date.now() + 24*60*60*1000;

        await user.save();

        const mailOption = {
            from:process.env.SENDER_EMAIL,
            to:user.email,
            subject:'Account Verification OTP',
            text:`Your OTP is ${otp}. Verify your account using this OTP.`
        }
        await transporter.sendMail(mailOption);

        return res.json({success:true,message:'Verification OTP sent on Email'})

    } catch (error) {
        return res.json({success:false,message:error.message});
    }
}

//verify the email with the otp
export const verifyEmail= async (req,res) =>{
        const {userId,otp} = req.body;

        if(!userId || !otp){
            return res.json({success:false,message:"Missing Details"});
        }

        try {
            const user = await userModel.findOne({userId});

            if(!user){
                return res.json({success:false,message:"User Not found"});
            }

            if(user.verifyOtp === '' || user.verifyOtp !== otp){
                return res.json({success:false,message:'Invalid OTP'});
            }

            if(user.verifyOtpExpiresAt < Date.now()){
                return res.json({success:false,message:'OTP expires'});
            }

            user.isAccountVerified = true;
            user.verifyOtp='';
            user.verifyOtpExpiresAt=0;

            await user.save();
            
            return res.json({success:true,message:'Email verified Successfully'}) ;
        } catch (error) {
            return res.json({success:false,message:error.message});
        }
}

//check if user is authenticated
export const isAuthenticated=async(req,res)=>{
        try {
            return res.json({success:true});
        } catch (error) {
            return res.json({success:false,message:error.message});
        }
}

//send password reset otp
export const sendResetOtp = async (req,res) =>{
    const {email} = req.body;

    if(!email){
        return res.json({success:false,message:"Email is Required"});
    }

    try {
        const user = await userModel.findOne({email});
        if(!user){
            return res.json({success:false,message:"User Not Found"});
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));

        user.resetOtp = otp;
        user.resetOtpExpiresAt= Date.now() + 15*60*1000;

        await user.save();

        const mailOption = {
            from:process.env.SENDER_EMAIL,
            to:user.email,
            subject:'Password Reset OTP',
            text:`Your OTP for resetting your password is ${otp}. Use this OTP to proceed with resetting your password.`
        }
        await transporter.sendMail(mailOption);

        return res.json({success:true,message:'OTP sent to your Email'})
    } catch (error) {
        return res.json({success:false,message:error.message});
    }
}

//Reset user Password
export const resetPassword = async (req,res) =>{
    const {email,otp,newPassword} = req.body;

    if(!email || !otp || !newPassword){
        return res.json({success:false,message:"Email , OTP &  New Password are required."})
    }

    try {
        const user = await userModel.findOne({email});

        if(!user){
            return res.json({success:false,message:"User Not found"});
        }

        if(user.resetOtp === '' || user.resetOtp !== otp){
            return res.json({success:false,message:"Invalid OTP"});
        }

        if(user.resetOtpExpiresAt < Date.now()){
            return res.json({success:false,message:"OTP Expired"});
        }

        const hashedPassword = await bcrypt.hash(newPassword,10);

        user.password= hashedPassword;
        user.resetOtp='',
        user.resetOtpExpiresAt= 0;

        await user.save();

        return res.json({success:true,message:"Password has been reset Successfully"});
        
    } catch (error) {
        return res.json({success:false,message:error.message});
    }
}