export const switchToNums = cat => {
  switch (cat) {
    case "Yleinen":
      return 1
    case "Blogi":
      return 29
    case "Uutiset":
      return 31
    case "Kuntapolitiikka":
      return 32
    case "Alkoholipolitiikka":
      return 33
    case "Verotus":
      return 34

    default:
      return cat
  }
}

export const switchToCat = cat => {
  switch (cat) {
    case 1:
      return "Yleinen"
    case 29:
      return "Blogi"
    case 31:
      return "Uutiset"
    case 32:
      return "Kuntapolitiikka"
    case 33:
      return "Alkoholipolitiikka"
    case 34:
      return "Verotus"

    default:
      break
  }
}
