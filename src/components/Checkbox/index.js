import React from "react"

import "./styles.scss"

const Checkbox = ({ label, isChecked, setIsChecked, id, name }) => {
  const handleChange = () => {
    setIsChecked(prev => !prev)
  }
  return (
    <div className="checkbox-wrapper">
      <label>
        <input
          id={id}
          name={name}
          className={isChecked ? "checked" : "unchecked"}
          type="checkbox"
          checked={isChecked}
          onChange={handleChange}
        />
        <span>{label}</span>
      </label>
    </div>
  )
}
export default Checkbox
