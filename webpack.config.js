var path = require('path');
var webpack = require('webpack');
var nodeExternals = require('webpack-node-externals');

module.exports = {
    entry: './index.js',
    target: 'node', // in order to ignore built-in modules like path, fs, etc.
    externals: [nodeExternals()], // in order to ignore all modules in node_modules folder
    resolve: {
        extensions: [".webpack.js", ".js", ".ts"]
    },
    output: {
        path: path.join(__dirname, 'bundle'),
        filename: 'etoken.bundle.js',
        library: 'etoken',
        libraryTarget: 'umd',
        umdNamedDefine: true
    },
    module: {
        rules: [
            {
                test: /(\.jsx|\.js)$/,
                loader: 'babel-loader',
                exclude: /(node_modules|bower_components)/
            },
            {
                test: /\.ts$/,
                loader: 'ts-loader'
            }
        ]
    }
};