const _ = require('lodash');

// Never pass user input to _.template(userInput) here.
console.log(_.map([1, 2], (x) => x * 2));
