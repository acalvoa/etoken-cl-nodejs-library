var path = require('path');
var nodeExternals = require('webpack-node-externals');

module.exports = {
    entry: './release/index.js',
    mode: 'production',
    target: 'node', // in order to ignore built-in modules like path, fs, etc.
    externals: [nodeExternals()], // in order to ignore all modules in node_modules folder
    resolve: {
        modules: ['node_modules'],
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
                exclude: /(node_modules)/
            },
            {
                test: /\.ts$/,
                loader: 'ts-loader'
            }
        ]
    }
};