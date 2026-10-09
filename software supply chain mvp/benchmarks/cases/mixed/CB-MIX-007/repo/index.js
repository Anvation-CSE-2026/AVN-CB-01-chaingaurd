const _ = require('lodash');

function legacy() {
  return _.template('<%= a %>');
}

console.log(_.omit({ a: 1 }, ['a']));
