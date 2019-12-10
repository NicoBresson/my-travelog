const mongoose = require('mongoose');
mongoose.Promise = global.Promise;
const slug = require('slugs');

const storeSchema = new mongoose.Schema({
    name: {
        type: String,
        trim: true,
        required: 'Please enter a store name!'
    },
    slug: String,
    description: {
        type: String,
        trime: true,
    },
    tags: [String],
    created: {
        type: Date,
        default: Date.now
    },
    location: {
        type: {
            type: String,
            default: 'Point'
        },
        coordinates: [{
            type: Number,
            required: 'You must supply coordinates'
        }],
        address: {
            type: String,
            required: 'You must supply an address!'
        }
    },
    photo: String,
    author: {
        type: mongoose.Schema.ObjectId,
        ref: 'User',
        required: 'You must supply an author'
    }
}, { toJSON: { virtuals: true }, toObject: { virtuals: true } });

// Define our indexes
storeSchema.index({
    name: 'text',
    description: 'text'
});

storeSchema.index({
    location: '2dsphere'
});


storeSchema.pre('save', async function(next) {
    if (!this.isModified('name')) {
        next(); // skip it
        return;
    }
    this.slug = slug(this.name);
    // find others storeas a have a slif od we, we-1, wes-2
    const slugRegEx = new RegExp(`^(${this.slug})((-[0-9]*$)?)$`, 'i');
    const storesWithSlug = await this.constructor.find({ slug: slugRegEx });
    if (storesWithSlug.length) {
        this.slug = `${this.slug}-${storesWithSlug.length+1}`;
    }


    next();
    // Make it more resilisent so that slugs are unique
})

storeSchema.statics.getTagsList = function() {
    return this.aggregate([
        { $unwind: '$tags' },
        { $group: { _id: '$tags', count: { $sum: 1 } } },
        { $sort: { count: -1 } }
    ]);
}

storeSchema.statics.getTopStores = function() {
    return this.aggregate([
        // Lookup Stores and populate their reviews
        {
            $lookup: {
                from: 'reviews',
                localField: '_id',
                foreignField: 'store',
                as: 'reviews'
            }
        },
        // filter for only items that have 2 reviews or more
        {
            $match: { 'reviews.1': { $exists: true } }
        },
        // add the average reviews fields
        //1) wiht project, recreating an object
        // {
        //     $project: {
        //         photo: '$$ROOT.photo',
        //         name: '$$ROOT.photo',
        //         reviews: '$$ROOT.reviews',
        //         slug: $$ROOT.slug,
        //         averageRating: { $avg: '$reviews.rating' }
        //     }
        // },
        //2) wiht addField, adding to existing object
        {
            $addFields: {
                averageRating: { $avg: '$reviews.rating' },
            }
        },
        // sort it by our own new field, hieghest reviews first
        { $sort: { averageRating: -1 } },
        // limit to at most 10
        { $limit: 10 }
    ])
}

//find reviews where the store _id property  === reviews store property
storeSchema.virtual('reviews', {
    ref: 'Review', // what model to link?
    localField: '_id', // which field on the store
    foreignField: 'store' // which field on the review
})

function autopopulate(next) {
    this.populate('reviews');
    next();
}

storeSchema.pre('find', autopopulate);
storeSchema.pre('findOne', autopopulate);

module.exports = mongoose.model('Store', storeSchema)