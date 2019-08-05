const formatDate = (date, format = "short", locale = "en-GB") => {
  try {
    const dateObj = new Date(date)
    const formattedDate = dateObj.toLocaleDateString(
      locale,
      format === "short"
        ? { month: "short", day: "2-digit" }
        : { year: "numeric", month: "2-digit", day: "2-digit" }
    )
    return formattedDate.replace(/\//g, ".")
  } catch (error) {
    return ""
  }
}

export default formatDate
