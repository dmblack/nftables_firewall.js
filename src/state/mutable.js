const checkSetObject = (setObject) => {
  return typeof Object.keys(setObject)[0] !== 'undefined'
}

module.exports = (state) => ({
  get: (property) => {
    return state[property] || undefined
  },
  set: (setObject) => {
    if (checkSetObject(setObject)) {
      let currentState = Object.assign({}, state)

      let targetProperty = Object.keys(setObject)[0]
      let targetValue = setObject[targetProperty]

      console.log('Attempting to set %s, with %s.', targetProperty, targetValue)
      let newState = Object.assign({ [targetProperty]: targetValue }, currentState)

      state = newState
    }
  }
})
