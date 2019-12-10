const passport = require('passport');
const crypto = require('crypto');
const mongoose = require('mongoose');
const User = mongoose.model('User');
const promisify = require('es6-promisify');
const mail = require('../handlers/mail');


exports.login = passport.authenticate('local', {
    dailureRedirect: '/login',
    failureFlash: 'Failed login !',
    successRedirect: '/',
    successFlash: 'You are now logged in!'
});

exports.logout = (req, res) => {
    req.logout();
    req.flash('success', 'You are now logged out!');
    res.redirect('/');
}

exports.isLoggedIn = (req, res, next) => {
    if (req.isAuthenticated()) {
        next();
        return;
    }
    req.flash('error', 'Oups, you are not logged in! Login to do that');
    res.redirect('/login');
}

exports.forgot = async (req, res) => {
    // 1 see if there is a user
    const user = await User.findOne({ email: req.body.email })
    if (!user) {
        req.flash('error', 'A password reset has been mailed to you'); // never say the user that the emailis invalid
        return res.redirect('/login');
    }
    // 2 set reset tokens and epiry on their account
    user.resetPasswordToken = crypto.randomBytes(20).toString('hex');
    user.resetPasswordExpires = Date.now() + 3600000;
    await user.save();
    // 3 send an email with the token
    const resetURL = `http://${req.headers.host}/account/reset/${user.resetPasswordToken}`;
    await mail.send({
        user,
        filename: 'password-reset',
        subject: 'Password Reset',
        resetURL
    });
    req.flash('success', `You have been emailed a password rset link.`);
    // 4 redirect to login page
    res.redirect('/login');
}

exports.reset = async (req, res) => {
    const user = await User.findOne({
        resetPasswordToken: req.params.token,
        resetPasswordExpires: { $gt: Date.now() }
    });
    if (!user) {
        req.flash('error', 'Password reset is invalid or has expored');
        return res.redirect('/login');
    }
    // if there is a user show the reset user form
    res.render('reset', { title: 'Reset your password' })
};

exports.confirmedPasswords = (req, res, next) => {
    if (req.body.password === req.body['password-confirm']) {
        next();
        return
    }
    req.flash('error', 'Passwords do not match');
    res.redirect('back');
}

exports.update = async (req, res) => {
    const user = await User.findOne({
        resetPasswordToken: req.params.token,
        resetPasswordExpires: { $gt: Date.now() }
    });
    console.log('HERE')
    if (!user) {
        req.flash('error', 'Invalid user'); // never say the user that the emailis invalid
        return res.redirect('/login');
    }
    const setPassword = promisify(user.setPassword, user);
    await setPassword(req.body.password);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    const updateUser = await user.save();
    await req.login(updateUser);
    req.flash('success', 'Nice! Your password has been updated');
    res.redirect('/');
};