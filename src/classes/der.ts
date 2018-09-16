export class Der {
    public static getDerProperties(subjectArray) {
        let subject = [];
        // Iterate the subject
        for (let i=0; i< subjectArray.length; i++) {
            let subject_object = {};
            for (let l=0; l< subjectArray[i].length; l++) {
                if (subjectArray[i][l].name === 'OBJECT_IDENTIFIER') {
                    subject_object['id'] = subjectArray[i][l].value.id;
                    subject_object['attr'] = subjectArray[i][l].value.data;
                    subject_object['attr_type'] = subjectArray[i][l].value.type;
                    subject_object['min_attr'] = subjectArray[i][l].value.data.split("").filter((char, index) => {
                        if(index === 0) return true;
                        if(char === char.toUpperCase()) return true;
                        return false;
                    }).join('').toUpperCase();
                } else {
                    subject_object['value_type'] = subjectArray[i][l].name;
                    subject_object['value'] = subjectArray[i][l].value;
                }
            }
            subject.push(subject_object);
        }
        return subject;
    }
}