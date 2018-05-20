const immutable = require('./immutable');
const mutable = require('./mutable');

module.exports = (type) => (initialState) => {
  let state = {};

  if (typeof initialState !== 'undefined') {
    state = initialState;
  }

  if (typeof type === 'string' && (type === 'mutable' || type === 'immutable')) {
    if (type === 'immutable') {
      return Object.freeze(Object.assign(
        state,
        immutable(state)
      ));
    }

    if (type === 'mutable') {
      return Object.assign(
        state,
        mutable(state)
      );
    }
  }

  return state;
};
