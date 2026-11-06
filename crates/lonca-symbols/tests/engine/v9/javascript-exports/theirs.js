exports.a = function () {
  return 1;
};

module.exports.b = () => 20;

module.exports = {
  c() {},
  d: function () {},
  e() {},
};
