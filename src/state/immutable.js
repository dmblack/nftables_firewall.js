module.exports = (state) => ({
  get: (property) => {
    return state.property || undefined;
  }
});
