exports.a = function () {
  return 1;
};

module.exports.b = () => 2;

module.exports = {
  c() {},
  d: function () {},
};
