const errorHandler = (err, req, res, next) => {
    console.error('Error caught by middleware:', err.stack);
    res.status(err.status || 500).json({ 
        error: err.message || 'Internal Server Error' 
    });
};

module.exports = errorHandler;