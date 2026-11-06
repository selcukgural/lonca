exports.a = function () {
  return 10;
};

module.exports.b = () => 2;

module.exports = {
  c() { x(); },
  d: function () {},
};
