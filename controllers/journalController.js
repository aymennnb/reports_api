const Journal = require('../models/Journal')

const getAllJournals = async (req, res) => {
    try {
        const journals = await Journal.find()
            .sort({ created_at: -1 })

        res.status(200).json({
            count: journals.length,
            journals,
        })
    } catch (error) {
        console.error('[getAllJournals]', error.message)

        res.status(500).json({
            message: 'Failed to fetch journals.',
        })
    }
}

module.exports = {
    getAllJournals,
}