const _ = require('lodash');

module.exports = function render(tpl, data) {
  return _.template(tpl)(data);
};
